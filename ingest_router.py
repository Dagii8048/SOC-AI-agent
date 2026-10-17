from fastapi import APIRouter, Header, Request, Depends, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, conint
from typing import List, Optional, Dict, Any, Literal
import os
import hmac
from graph_loader import load_event

router = APIRouter()

# --- Pydantic Schema ---
class AlertSchema(BaseModel):
    id: str
    level: conint(ge=0, le=15) = 0
    name: str = ""
    timestamp: int
    mitre: List[str] = Field(default_factory=list)

class HostSchema(BaseModel):
    hostname: str
    ip: Optional[str] = None
    os: Optional[str] = None

class UserSchema(BaseModel):
    username: str
    domain: Optional[str] = None
    admin: Optional[bool] = None
    failed_logins: Optional[int] = None
    last_failed: Optional[int] = None

class ProcessSchema(BaseModel):
    pid: int
    start_time: Optional[int] = None
    name: str = ""
    path: Optional[str] = None
    args: Optional[str] = None
    hash: Optional[str] = None
    parent: Optional[Dict[str, Any]] = None # Could define full schema but keep simple to avoid circular deps

class NetworkSchema(BaseModel):
    src_ip: Optional[str] = None
    dest_ip: str
    dest_port: int
    protocol: str

class FileSchema(BaseModel):
    path: str
    hash: Optional[str] = None
    size: Optional[int] = None
    op: Literal["read", "write"]

class EventSchema(BaseModel):
    alert: AlertSchema
    host: Optional[HostSchema] = None
    user: Optional[UserSchema] = None
    process: Optional[ProcessSchema] = None
    network: List[NetworkSchema] = Field(default_factory=list)
    files: List[FileSchema] = Field(default_factory=list)
    logged_in_hosts: List[str] = Field(default_factory=list)
    scanned_hosts: List[str] = Field(default_factory=list)

class IngestRequest(BaseModel):
    events: List[EventSchema]

# ----------------------

def get_driver(req: Request):
    if "app" in req.scope:
        return getattr(req.scope["app"].state, "neo4j_driver", None)
    return None

@router.post("/ingest/events")
async def ingest_events(
    request: IngestRequest,
    req: Request,
    x_api_key: str = Header(None)
):
    expected_key = os.environ.get("INGEST_API_KEY")
    if not expected_key:
        return JSONResponse(status_code=503, content={"detail": "INGEST_API_KEY not configured"})
    if not x_api_key or not hmac.compare_digest(x_api_key, expected_key):
        return JSONResponse(status_code=401, content={"detail": "Unauthorized"})

    events = request.events
    if len(events) > 500:
        return JSONResponse(status_code=413, content={"detail": "Payload Too Large"})

    rejected = []

    driver = get_driver(req)
    if not driver:
        # Fail closed if driver is missing
        raise HTTPException(status_code=500, detail="Database driver not available")

    with driver.session() as session:
        for i, event in enumerate(events):
            try:
                # Convert back to dict for the loader since we validated it
                load_event(session, event.model_dump(exclude_none=True))
            except Exception as e:
                rejected.append({"index": i, "reason": str(e)})

    return {"accepted": len(events) - len(rejected), "rejected": rejected}

def get_alert_subgraph(driver, alert_id):
    # Fix: Get the alert first, then optionally match relationships.
    query = """
    MATCH (a:Alert {id: $alert_id})
    OPTIONAL MATCH p=(a)-[]-(n)
    WHERE type(relationships(p)[0]) IN ['TRIGGERED_BY', 'DETECTED_ON', 'OWNS', 'SPAWNED', 'RUNS_ON', 'CONNECTED_TO', 'READS', 'WRITES']
    OPTIONAL MATCH p2=(n)-[]-(m)
    WHERE type(relationships(p2)[0]) IN ['TRIGGERED_BY', 'DETECTED_ON', 'OWNS', 'SPAWNED', 'RUNS_ON', 'CONNECTED_TO', 'READS', 'WRITES']
    OPTIONAL MATCH p3=(m)-[]-(o)
    WHERE type(relationships(p3)[0]) IN ['TRIGGERED_BY', 'DETECTED_ON', 'OWNS', 'SPAWNED', 'RUNS_ON', 'CONNECTED_TO', 'READS', 'WRITES']
    RETURN a AS root_node,
           nodes(p) AS n1, relationships(p) AS r1,
           nodes(p2) AS n2, relationships(p2) AS r2,
           nodes(p3) AS n3, relationships(p3) AS r3
    LIMIT 200
    """
    with driver.session() as session:
        result = session.run(query, alert_id=alert_id)
        nodes = {}
        edges = []

        has_record = False

        def add_node(node):
            if node:
                nodes[node.element_id] = {"id": node.element_id, "labels": list(node.labels), "props": dict(node)}

        def add_edge(edge):
            if edge:
                edge_obj = {"from": edge.start_node.element_id, "to": edge.end_node.element_id, "type": edge.type}
                if edge_obj not in edges:
                    edges.append(edge_obj)

        for record in result:
            has_record = True
            add_node(record["root_node"])
            if record["n1"]:
                for node in record["n1"]: add_node(node)
            if record["r1"]:
                for edge in record["r1"]: add_edge(edge)
            if record["n2"]:
                for node in record["n2"]: add_node(node)
            if record["r2"]:
                for edge in record["r2"]: add_edge(edge)
            if record["n3"]:
                for node in record["n3"]: add_node(node)
            if record["r3"]:
                for edge in record["r3"]: add_edge(edge)

        if not has_record:
            return {"nodes": [], "edges": []}

        return {"nodes": list(nodes.values()), "edges": edges}

def investigate_alert(driver, alert_id):
    subgraph = get_alert_subgraph(driver, alert_id)
    if not subgraph["nodes"]:
        return {"result": "not-found"}
    return {"result": "success", "subgraph": subgraph}
