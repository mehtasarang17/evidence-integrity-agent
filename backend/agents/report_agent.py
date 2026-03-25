"""Report Generation Agent — Synthesizes all findings into a comprehensive report."""

import json
import logging
from agents.state import EvidenceState
from utils.bedrock_client import get_llm
from langchain_core.messages import HumanMessage, SystemMessage

logger = logging.getLogger(__name__)

REPORT_SYSTEM_PROMPT = """You are a digital forensics expert generating evidence integrity reports. 
You will receive analysis results from multiple specialized agents and must synthesize them into a comprehensive, 
clear, and actionable report.

Your report must be precise, professional, and suitable for legal or compliance review.
Always base your conclusions on the evidence provided — never speculate without basis."""

REPORT_PROMPT_TEMPLATE = """Based on the following multi-agent analysis of digital evidence, generate a comprehensive integrity report.

## Evidence File
- **Filename**: {filename}
- **File Type**: {file_type}
- **MIME Type**: {mime_type}

## Metadata Agent Findings
{metadata_summary}

## Hash Verification Findings
{hash_summary}

## Visual Analysis Findings
{visual_summary}

## RAG Pattern Matching Findings
{rag_summary}

## Agent Risk Scores
{risk_scores}

Generate a report in this exact JSON format:
{{
    "authenticity_score": <0-100 integer>,
    "tamper_risk": "<Low|Medium|High|Critical>",
    "executive_summary": "A 3-4 sentence executive summary of the findings",
    "detailed_findings": [
        {{
            "agent": "agent name",
            "category": "finding category",
            "finding": "detailed description",
            "severity": "low|medium|high|critical",
            "recommendation": "what to do about this"
        }}
    ],
    "integrity_indicators": {{
        "positive": ["list of factors supporting authenticity"],
        "negative": ["list of factors suggesting tampering"]
    }},
    "recommendations": ["list of recommended actions"],
    "methodology": "Brief description of the analysis methodology used"
}}

IMPORTANT: 
- The authenticity_score should be a weighted average considering all agent scores
- tamper_risk should reflect the overall risk level
- Be specific and evidence-based in your findings
- Respond ONLY with the JSON, no other text"""


def report_agent(state: EvidenceState) -> dict:
    """Generate the final comprehensive report from all agent findings."""
    logger.info(f"[ReportAgent] Generating report for: {state['original_filename']}")

    try:
        # Format findings for the LLM
        prompt = _format_prompt(state)

        # Generate report via Nova Lite
        llm = get_llm(temperature=0.1, max_tokens=3000)

        messages = [
            SystemMessage(content=REPORT_SYSTEM_PROMPT),
            HumanMessage(content=prompt),
        ]

        response = llm.invoke(messages)

        # Parse the JSON report
        content = response.content.strip()
        if content.startswith("```"):
            content = content.split("\n", 1)[1].rsplit("```", 1)[0]
        report = json.loads(content)

        # Ensure required fields
        authenticity_score = report.get("authenticity_score", _calculate_fallback_score(state))
        tamper_risk = report.get("tamper_risk", _determine_risk_level(authenticity_score))

        logger.info(f"[ReportAgent] Score: {authenticity_score}, Risk: {tamper_risk}")
        return {
            "report": report,
            "authenticity_score": float(authenticity_score),
            "tamper_risk": tamper_risk,
            "agents_completed": state.get("agents_completed", []) + ["report"],
        }

    except Exception as e:
        logger.error(f"[ReportAgent] Error: {e}")
        fallback_score = _calculate_fallback_score(state)
        return {
            "report": {
                "authenticity_score": fallback_score,
                "tamper_risk": _determine_risk_level(fallback_score),
                "executive_summary": f"Report generation encountered an error: {str(e)}. "
                                     f"Fallback score based on individual agent results: {fallback_score}",
                "detailed_findings": [],
                "error": str(e),
            },
            "authenticity_score": float(fallback_score),
            "tamper_risk": _determine_risk_level(fallback_score),
            "errors": state.get("errors", []) + [f"ReportAgent: {e}"],
            "agents_completed": state.get("agents_completed", []) + ["report"],
        }


def _format_prompt(state: EvidenceState) -> str:
    """Format the prompt with all agent findings."""

    # Metadata summary
    meta = state.get("metadata_results", {})
    metadata_summary = json.dumps(meta, indent=2, default=str) if meta else "No metadata analysis available"

    # Hash summary
    hash_info = state.get("hash_results", {})
    hash_summary = json.dumps(hash_info, indent=2, default=str) if hash_info else "No hash analysis available"

    # Visual summary
    visual = state.get("visual_results", {})
    visual_summary = json.dumps(visual, indent=2, default=str) if visual else "No visual analysis available"

    # RAG summary
    rag = state.get("rag_results", {})
    rag_summary = json.dumps(rag, indent=2, default=str) if rag else "No pattern matching available"

    # Collect risk scores
    risk_scores = []
    for agent_name, key in [("Metadata", "metadata_results"), ("Hash", "hash_results"),
                             ("Visual", "visual_results"), ("RAG", "rag_results")]:
        agent_data = state.get(key, {})
        risk = agent_data.get("risk_contribution", {})
        if risk:
            risk_scores.append(f"- {agent_name}: {risk.get('score', 'N/A')}/100 ({risk.get('reasoning', '')})")

    return REPORT_PROMPT_TEMPLATE.format(
        filename=state.get("original_filename", "Unknown"),
        file_type=state.get("file_type", "Unknown"),
        mime_type=state.get("mime_type", "Unknown"),
        metadata_summary=metadata_summary,
        hash_summary=hash_summary,
        visual_summary=visual_summary,
        rag_summary=rag_summary,
        risk_scores="\n".join(risk_scores) if risk_scores else "No risk scores available",
    )


def _calculate_fallback_score(state: EvidenceState) -> int:
    """Calculate a fallback score from individual agent results."""
    scores = []
    weights = []

    for key, weight in [("metadata_results", 0.25), ("hash_results", 0.2),
                         ("visual_results", 0.35), ("rag_results", 0.2)]:
        agent_data = state.get(key, {})
        risk = agent_data.get("risk_contribution", {})
        if risk and "score" in risk:
            scores.append(risk["score"] * weight)
            weights.append(weight)

    if not scores:
        return 50  # Default uncertain score

    total_weight = sum(weights)
    return int(sum(scores) / total_weight) if total_weight > 0 else 50


def _determine_risk_level(score: int) -> str:
    """Determine risk level from authenticity score."""
    if score >= 80:
        return "Low"
    elif score >= 60:
        return "Medium"
    elif score >= 40:
        return "High"
    else:
        return "Critical"
