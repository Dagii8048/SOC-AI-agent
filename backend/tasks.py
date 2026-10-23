"""
tasks.py
The investigation, run as a background Celery task.

What changed from the first version:
  - The graph work (find alert, match patterns, score confidence) now comes
    from Amir's graph_queries.investigate_alert(). We no longer keep our own
    copy of his pattern code.
  - "Alert not found" is reported with an explicit found=False flag, instead
    of an error message hidden inside a "success" result.
  - The briefing now comes from Teferi's LangGraph agent (orchestrator/agent.py).
    If that agent can't run yet (missing libraries, Qdrant/Ollama not running),
    the task still finishes and the briefing explains why.
"""
import repo_paths  # noqa: F401  (must stay first: makes graph/ importable)

from dotenv import load_dotenv
load_dotenv()

import os

from neo4j import GraphDatabase

from celery_app import celery_app
from graph_queries import investigate_alert  # Amir's code, in graph/

NEO4J_URI = os.environ.get("NEO4J_URI", "bolt://localhost:7687")
NEO4J_AUTH = (
    os.environ.get("NEO4J_USER", "neo4j"),
    os.environ.get("NEO4J_PASSWORD", "password"),
)


def _load_alert_fields(driver, alert_id: str) -> dict:
    """Read the alert's name and severity from Neo4j (the agent needs them)."""
    with driver.session(database=os.environ.get("NEO4J_DATABASE") or None) as session:
        record = session.run(
            "MATCH (a:Alert {id: $alert_id}) RETURN a.name AS name, a.severity AS severity",
            alert_id=alert_id,
        ).single()
    name = (record["name"] if record else None) or "Unknown alert"
    severity = (record["severity"] if record else None) or "Low"
    return {"name": name, "severity": severity}


def _generate_briefing(driver, alert_id: str, result: dict):
    """Ask Teferi's LangGraph agent for the analyst briefing."""
    try:
        fields = _load_alert_fields(driver, alert_id)

        # Imported here (not at the top) so a problem inside the agent can't
        # stop the whole worker from starting.
        # TEMPORARY WORKAROUND: agent.py loads its model files using paths
        # relative to the current folder ("../ml-rag/..."), so we step into
        # orchestrator/ while it loads. Teferi can remove this by building
        # those paths from repo_root, which agent.py already computes.
        previous_dir = os.getcwd()
        os.chdir(repo_paths.ORCHESTRATOR_DIR)
        try:
            import agent
        finally:
            os.chdir(previous_dir)

        # The real investigation result goes to the agent as its graph data.
        graph_context = {
            "alert": {"id": alert_id, "name": fields["name"], "severity": fields["severity"]},
            "confidence": result["confidence"],
            "matched_patterns": result["matched_patterns"],
            "kill_chain_detected": result["kill_chain_detected"],
            "kill_chain_name": result["kill_chain_name"],
        }

        final_state = agent.app.invoke({
            "alert_id": alert_id,
            "alert_type": fields["name"],
            "severity": fields["severity"],
            "description": fields["name"],  # Alert nodes have no separate description yet
            "graph_context": graph_context,
        })
        return final_state.get("final_briefing")
    except Exception as exc:  # noqa: BLE001 - we want ANY failure reported, not crashed
        return {"error": f"Briefing unavailable: {type(exc).__name__}: {exc}"}


@celery_app.task(name="investigate_alert")
def investigate_alert_task(alert_id: str):
    driver = GraphDatabase.driver(NEO4J_URI, auth=NEO4J_AUTH)
    try:
        result = investigate_alert(driver, alert_id)

        if not result["found"]:
            return {"found": False, "alert_id": alert_id}

        llm_invoked = result["confidence"] != "LOW"
        briefing = _generate_briefing(driver, alert_id, result) if llm_invoked else None

        return {
            "found": True,
            "alert_id": alert_id,
            "confidence": result["confidence"],
            "matched_patterns": result["matched_patterns"],
            "kill_chain_detected": result["kill_chain_detected"],
            "kill_chain_name": result["kill_chain_name"],
            "llm_invoked": llm_invoked,
            "briefing": briefing,
        }
    finally:
        driver.close()
