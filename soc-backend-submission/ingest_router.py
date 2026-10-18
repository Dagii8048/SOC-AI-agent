from fastapi import APIRouter, Header, Request, Depends, HTTPException, Body
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, conint, constr, ValidationError
from typing import List, Optional, Dict, Any, Literal
import os
import hmac
from graph_loader import load_event

router = APIRouter()

class AlertSchema(BaseModel):
    id: str
    level: conint(ge=0, le=15) = 0
    name: constr(max_length=256) = ""
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

class ProcessChildSchema(BaseModel):
    pid: int
    start_time: Optional[int] = None
    name: constr(max_length=256) = ""
    args: Optional[constr(max_length=4096)] = None

class ProcessParentSchema(BaseModel):
    pid: int
    start_time: Optional[int] = None
    name: constr(max_length=256) = ""
    path: Optional[constr(max_length=1024)] = None
    args: Optional[constr(max_length=4096)] = None
    hash: Optional[str] = None

class ProcessSchema(BaseModel):
    pid: int
    start_time: Optional[int] = None
    name: constr(max_length=256) = ""
    path: Optional[constr(max_length=1024)] = None
    args: Optional[constr(max_length=4096)] = None
    hash: Optional[str] = None
    parent: Optional[ProcessParentSchema] = None
    children: List[ProcessChildSchema] = Field(default_factory=list)

class NetworkSchema(BaseModel):
    src_ip: Optional[str] = None
    dest_ip: str
    dest_port: int
    protocol: str

class FileSchema(BaseModel):
    path: constr(max_length=1024)
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

def verify_api_key(x_api_key: str = Header(None)):
    expected_key = os.environ.get("INGEST_API_KEY")
    if not expected_key:
        raise HTTPException(status_code=503, detail="INGEST_API_KEY not configured")
    if not x_api_key or not hmac.compare_digest(x_api_key, expected_key):
        raise HTTPException(status_code=401, detail="Unauthorized")

def enforce_content_length(request: Request):
    content_length = request.headers.get("content-length")
    if content_length and int(content_length) > 10_000_000:
        raise HTTPException(status_code=413, detail="Payload Too Large")

_neo4j_driver = None

def get_driver():
    global _neo4j_driver
    if not _neo4j_driver:
        from neo4j import GraphDatabase
        uri = os.environ.get("NEO4J_URI", "bolt://localhost:7687")
        user = os.environ.get("NEO4J_USER", "neo4j")
        password = os.environ.get("NEO4J_PASSWORD", "password")
        _neo4j_driver = GraphDatabase.driver(uri, auth=(user, password))
    return _neo4j_driver

def close_driver():
    global _neo4j_driver
    if _neo4j_driver:
        _neo4j_driver.close()
        _neo4j_driver = None

@router.post("/ingest/events", dependencies=[Depends(verify_api_key), Depends(enforce_content_length)])
def ingest_events(
    payload: dict = Body(...),
    driver = Depends(get_driver)
):
    events = payload.get("events", [])
    if len(events) > 500:
        return JSONResponse(status_code=413, content={"detail": "Payload Too Large"})

    accepted = 0
    rejected = []

    with driver.session() as session:
        for i, raw_event in enumerate(events):
            try:
                validated_event = EventSchema(**raw_event)
                load_event(session, validated_event.model_dump(exclude_none=True))
                accepted += 1
            except ValidationError as ve:
                rejected.append({"index": i, "reason": "Validation Error"})
            except Exception as e:
                rejected.append({"index": i, "reason": str(e)})

    return {"accepted": accepted, "rejected": rejected}
