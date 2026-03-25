"""LangGraph Workflow — Orchestrates the multi-agent evidence analysis pipeline."""

import logging
from langgraph.graph import StateGraph, END
from agents.state import EvidenceState
from agents.metadata_agent import metadata_agent
from agents.hash_agent import hash_agent
from agents.visual_agent import visual_agent
from agents.rag_agent import rag_agent
from agents.report_agent import report_agent

logger = logging.getLogger(__name__)


def create_evidence_graph() -> StateGraph:
    """
    Create the LangGraph workflow for evidence analysis.

    Pipeline:
        ┌──────────────┐     ┌────────────┐     ┌──────────────┐
        │ Metadata Agent│     │ Hash Agent  │     │ Visual Agent  │
        └──────┬───────┘     └─────┬──────┘     └──────┬───────┘
               │                   │                    │
               └─────────┬────────┘                    │
                         │                             │
                    ┌────▼─────────────────────────────▼─┐
                    │         RAG Pattern Agent            │
                    └────────────┬────────────────────────┘
                                 │
                    ┌────────────▼────────────────────────┐
                    │       Report Generation Agent        │
                    └────────────┬────────────────────────┘
                                 │
                               [END]
    """
    workflow = StateGraph(EvidenceState)

    # Add agent nodes
    workflow.add_node("metadata_agent", metadata_agent)
    workflow.add_node("hash_agent", hash_agent)
    workflow.add_node("visual_agent", visual_agent)
    workflow.add_node("rag_agent", rag_agent)
    workflow.add_node("report_agent", report_agent)

    # Set entry point — all three analysis agents run from start
    workflow.set_entry_point("metadata_agent")

    # Parallel execution: metadata → hash → visual → rag → report
    # LangGraph will run these sequentially in this chain
    workflow.add_edge("metadata_agent", "hash_agent")
    workflow.add_edge("hash_agent", "visual_agent")
    workflow.add_edge("visual_agent", "rag_agent")
    workflow.add_edge("rag_agent", "report_agent")
    workflow.add_edge("report_agent", END)

    return workflow.compile()


# Pre-compiled graph for reuse
evidence_graph = None


def get_evidence_graph():
    """Get or create the compiled evidence analysis graph."""
    global evidence_graph
    if evidence_graph is None:
        evidence_graph = create_evidence_graph()
    return evidence_graph


def run_analysis(file_id: str, file_path: str, original_filename: str,
                 file_type: str, mime_type: str) -> dict:
    """Run the full evidence analysis pipeline."""
    logger.info(f"Starting analysis for {original_filename} (ID: {file_id})")

    graph = get_evidence_graph()

    # Initialize state
    initial_state: EvidenceState = {
        "file_id": file_id,
        "file_path": file_path,
        "original_filename": original_filename,
        "file_type": file_type,
        "mime_type": mime_type,
        "metadata_results": {},
        "hash_results": {},
        "visual_results": {},
        "rag_results": {},
        "report": {},
        "authenticity_score": 0.0,
        "tamper_risk": "Unknown",
        "agents_completed": [],
        "errors": [],
    }

    # Run the graph
    result = graph.invoke(initial_state)

    logger.info(
        f"Analysis complete for {original_filename}: "
        f"Score={result.get('authenticity_score')}, "
        f"Risk={result.get('tamper_risk')}, "
        f"Agents={result.get('agents_completed')}"
    )

    return result
