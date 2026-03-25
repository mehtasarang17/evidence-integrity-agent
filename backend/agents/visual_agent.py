"""Visual Tampering Detection Agent — Uses Amazon Nova Lite vision to detect image manipulation."""

import base64
import logging
from agents.state import EvidenceState
from utils.image_utils import compute_ela
from utils.file_utils import is_image_file
from utils.bedrock_client import get_llm
from langchain_core.messages import HumanMessage

logger = logging.getLogger(__name__)

VISUAL_ANALYSIS_PROMPT = """You are a forensic image analyst specializing in detecting tampered or fabricated digital evidence. Analyze this image for signs of manipulation.

Check for these indicators:
1. **Pixel-level inconsistencies**: Look for artifacts at edit boundaries, mismatched compression levels, copy-paste artifacts
2. **Font and text anomalies**: Inconsistent font rendering, text that doesn't match the UI/application style, unnatural kerning
3. **UI element irregularities**: Misaligned components, incorrect spacing, elements that don't match the expected application design
4. **Color and lighting issues**: Inconsistent lighting, color banding at edit boundaries, unnatural shadows or highlights
5. **Compression artifacts**: Different JPEG quality levels in different regions, suggesting parts were edited separately
6. **Screenshot authenticity**: Check if standard OS elements (taskbar, status bar, window chrome) appear genuine
7. **Content consistency**: Does the content shown make logical sense? Are there any contradictions in displayed information?

Provide your analysis in this exact JSON format:
{
    "tampering_likelihood": "none|low|medium|high|critical",
    "findings": [
        {
            "category": "category name",
            "description": "what you found",
            "severity": "low|medium|high"
        }
    ],
    "authentic_indicators": ["list of signs suggesting the image IS authentic"],
    "suspicious_indicators": ["list of signs suggesting possible tampering"],
    "overall_assessment": "A 2-3 sentence summary of your assessment",
    "confidence": 0.85
}

Respond ONLY with the JSON, no other text."""


def visual_agent(state: EvidenceState) -> dict:
    """Analyze evidence visually for tampering indicators."""
    logger.info(f"[VisualAgent] Analyzing: {state['original_filename']}")

    try:
        file_path = state["file_path"]
        file_type = state["file_type"]

        # Only perform visual analysis on images
        if file_type != "image" or not is_image_file(file_path):
            results = {
                "status": "skipped",
                "reason": "Visual analysis only applies to image files",
                "risk_contribution": {"score": 100, "deductions": 0, "reasoning": "N/A for non-image files"},
            }
            return {
                "visual_results": results,
                "agents_completed": state.get("agents_completed", []) + ["visual"],
            }

        # Run Error Level Analysis
        ela_results = compute_ela(file_path)

        # Run Nova Lite Vision analysis
        vision_results = _analyze_with_vision(file_path)

        # Combine results
        results = {
            "status": "completed",
            "ela": ela_results,
            "vision_analysis": vision_results,
            "risk_contribution": _calculate_risk(ela_results, vision_results),
        }

        logger.info(f"[VisualAgent] Tampering likelihood: {vision_results.get('tampering_likelihood', 'unknown')}")
        return {
            "visual_results": results,
            "agents_completed": state.get("agents_completed", []) + ["visual"],
        }

    except Exception as e:
        logger.error(f"[VisualAgent] Error: {e}")
        return {
            "visual_results": {"status": "error", "error": str(e)},
            "errors": state.get("errors", []) + [f"VisualAgent: {e}"],
            "agents_completed": state.get("agents_completed", []) + ["visual"],
        }


def _analyze_with_vision(file_path: str) -> dict:
    """Send image to Amazon Nova Lite for visual analysis."""
    try:
        # Read and encode the image
        with open(file_path, "rb") as f:
            image_data = base64.b64encode(f.read()).decode("utf-8")

        # Detect mime type
        ext = file_path.rsplit(".", 1)[-1].lower()
        mime_map = {"png": "image/png", "jpg": "image/jpeg", "jpeg": "image/jpeg",
                    "gif": "image/gif", "webp": "image/webp", "bmp": "image/bmp"}
        mime_type = mime_map.get(ext, "image/png")

        llm = get_llm(temperature=0, max_tokens=2000)

        message = HumanMessage(
            content=[
                {"type": "text", "text": VISUAL_ANALYSIS_PROMPT},
                {
                    "type": "image",
                    "source": {
                        "type": "base64",
                        "media_type": mime_type,
                        "data": image_data,
                    },
                },
            ]
        )

        response = llm.invoke([message])

        import json
        # Try to parse JSON from response
        content = response.content.strip()
        if content.startswith("```"):
            content = content.split("\n", 1)[1].rsplit("```", 1)[0]
        return json.loads(content)

    except Exception as e:
        logger.error(f"[VisualAgent] Vision API error: {e}")
        return {
            "tampering_likelihood": "unknown",
            "findings": [],
            "authentic_indicators": [],
            "suspicious_indicators": [],
            "overall_assessment": f"Vision analysis could not be completed: {str(e)}",
            "confidence": 0.0,
        }


def _calculate_risk(ela_results: dict, vision_results: dict) -> dict:
    """Calculate risk contribution from visual analysis."""
    score = 100

    # ELA-based deductions
    if ela_results.get("suspicious"):
        score -= 20

    # Vision-based deductions
    likelihood = vision_results.get("tampering_likelihood", "unknown")
    likelihood_deductions = {
        "none": 0, "low": 10, "medium": 25, "high": 40, "critical": 60, "unknown": 5,
    }
    score -= likelihood_deductions.get(likelihood, 5)

    # Additional deductions for findings
    findings = vision_results.get("findings", [])
    high_findings = sum(1 for f in findings if f.get("severity") == "high")
    score -= min(high_findings * 5, 20)

    reasoning_parts = []
    if ela_results.get("suspicious"):
        reasoning_parts.append(f"ELA detected anomalies (avg error: {ela_results.get('average_error_level', 'N/A')})")
    reasoning_parts.append(f"Vision analysis: {likelihood} tampering likelihood")
    if findings:
        reasoning_parts.append(f"{len(findings)} findings ({high_findings} high severity)")

    return {
        "score": max(0, score),
        "deductions": 100 - max(0, score),
        "reasoning": ". ".join(reasoning_parts),
    }
