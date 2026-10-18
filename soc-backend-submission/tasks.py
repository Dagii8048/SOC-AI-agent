"""
tasks.py
The actual investigation logic, run as a background Celery task
instead of inline inside the FastAPI request.
"""
from dotenv import load_dotenv
load_dotenv()

import os

from neo4j import GraphDatabase

from celery_app import celery_app
from pattern_library import match_patterns
from pattern_evaluator import evaluate_patterns

NEO4J_URI = os.environ.get("NEO4J_URI", "bolt://localhost:7687")
NEO4J_AUTH = (
    os.environ.get("NEO4J_USER", "neo4j"),
    os.environ.get("NEO4J_PASSWORD", "password"),
)


@celery_app.task(name="investigate_alert")
def investigate_alert_task(alert_id: str):
    driver = GraphDatabase.driver(NEO4J_URI, auth=NEO4J_AUTH)
    try:
        matched = match_patterns(driver, alert_id)

        if not matched:
            with driver.session() as session:
                exists = session.run(
                    "MATCH (a:Alert {id: $alert_id}) RETURN a LIMIT 1",
                    alert_id=alert_id,
                ).peek()
            if exists is None:
                return {"error": f"Alert {alert_id} not found"}

        confidence, kill_chain_detected, kill_chain_name = evaluate_patterns(matched)
        llm_invoked = confidence != "LOW"

        briefing = None
        if llm_invoked:
            # TODO (Role 1): replace with the real LangGraph call.
            briefing = {
                "summary": "Mock briefing -- LangGraph agent not yet wired in.",
                "threat_level": confidence,
            }

        return {
            "alert_id": alert_id,
            "confidence": confidence,
            "matched_patterns": matched,
            "kill_chain_detected": kill_chain_detected,
            "kill_chain_name": kill_chain_name,
            "llm_invoked": llm_invoked,
            "briefing": briefing,
        }
    finally:
        driver.close()
