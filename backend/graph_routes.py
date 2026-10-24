"""
graph_routes.py
Read-only routes the dashboard needs to show REAL graph data:

  GET /alerts                      the alerts in the graph, newest first
  GET /alerts/{alert_id}/graph     that alert's attack graph, ready for Cytoscape

The graph work itself is in graph/graph_queries.py (get_alert_subgraph,
to_cytoscape). This file only exposes it over HTTP.
"""
import repo_paths  # noqa: F401  (must stay first: makes graph/ importable)

import os

from fastapi import APIRouter, Depends, HTTPException, Query

import ingest_router  # shared Neo4j driver (get_driver) lives here
from graph_queries import get_alert_subgraph, to_cytoscape

router = APIRouter()

ALERTS_QUERY = """
MATCH (a:Alert)
OPTIONAL MATCH (a)-[:DETECTED_ON]->(h:Host)
WITH a, collect(h.hostname)[0] AS hostname
RETURN a.id AS id, a.name AS name, a.severity AS severity,
       a.level AS level, a.timestamp AS timestamp, hostname
ORDER BY a.timestamp DESC
LIMIT $limit
"""


def list_alerts(driver, limit: int = 50) -> list:
    """Newest alerts first: id, name, severity, level, timestamp (ms), hostname."""
    with driver.session(database=os.environ.get("NEO4J_DATABASE") or None) as session:
        rows = session.run(ALERTS_QUERY, limit=limit)
        return [
            {
                "id": r["id"],
                "name": r["name"] or "Unknown alert",
                "severity": r["severity"] or "Low",
                "level": r["level"],
                "timestamp": r["timestamp"],
                "hostname": r["hostname"],
            }
            for r in rows
        ]


def alert_graph(driver, alert_id: str) -> dict:
    """The alert's subgraph as {"nodes": [...], "edges": [...]} for Cytoscape."""
    subgraph = get_alert_subgraph(driver, alert_id)
    if not subgraph["nodes"]:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found")
    return to_cytoscape(subgraph)


@router.get("/alerts")
def get_alerts(
    limit: int = Query(50, ge=1, le=200),
    driver=Depends(ingest_router.get_driver),
):
    return {"alerts": list_alerts(driver, limit)}


@router.get("/alerts/{alert_id}/graph")
def get_alert_graph(alert_id: str, driver=Depends(ingest_router.get_driver)):
    return alert_graph(driver, alert_id)
