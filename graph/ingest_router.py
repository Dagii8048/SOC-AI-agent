from fastapi import APIRouter, Header, Request, Depends, HTTPException, Body
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, conint, constr, ValidationError, field_validator
from typing import Annotated, List, Optional, Dict, Any, Literal
from pydantic import BeforeValidator
import os
import hmac
import logging
from graph_loader import load_event

logger = logging.getLogger(__name__)
router = APIRouter()

def truncate_head_tail(value, limit):
    """Shorten an over-long string to at most `limit` characters.

    Keeps the START and the END and puts a marker in the middle. The END must
    be kept: in long encoded commands the payload is usually at the end.
    Non-strings and strings within the limit are returned unchanged.
    """
    if not isinstance(value, str) or len(value) <= limit:
        return value
    # len(value) is an upper bound for the number removed, so the marker built
    # here is never shorter than the final one and the result fits in `limit`.
    keep = limit - len(f" ...[truncated {len(value)} chars]... ")
    removed = len(value) - keep
    marker = f" ...[truncated {removed} chars]... "
    head = keep // 2
    tail = keep - head
    return value[:head] + marker + value[len(value) - tail:]

def _shorten(limit):
    return BeforeValidator(lambda v: truncate_head_tail(v, limit))

# Evidence fields: too long -> shortened (head + tail), event still accepted.
# Sending a huge value must never be a way to get an event rejected.
Text256 = Annotated[str, _shorten(256)]
Text1024 = Annotated[str, _shorten(1024)]
Text4096 = Annotated[str, _shorten(4096)]

# Identity fields (alert id, hostname, username, destination IP, host lists)
# are NOT shortened: a changed value would point at a different node.
# Too long -> the event is rejected, as before.


class AlertSchema(BaseModel):
    id: constr(max_length=256)
    level: conint(ge=0, le=15) = 0
    name: Text256 = ""
    timestamp: int
    mitre: List[str] = Field(default_factory=list)

    @field_validator('timestamp')
    def check_timestamp_ms(cls, v):
        if v < 100000000000:
            raise ValueError("timestamp must be epoch milliseconds")
        return v

class HostSchema(BaseModel):
    hostname: constr(max_length=256)
    ip: Optional[Text256] = None
    os: Optional[Text256] = None

class UserSchema(BaseModel):
    username: constr(max_length=256)
    domain: Optional[Text256] = None
    admin: Optional[bool] = None
    failed_logins: Optional[int] = None
    last_failed: Optional[int] = None

class ProcessChildSchema(BaseModel):
    pid: int
    start_time: Optional[int] = None
    name: Text256 = ""
    args: Optional[Text4096] = None

class ProcessParentSchema(BaseModel):
    pid: int
    start_time: Optional[int] = None
    name: Text256 = ""
    path: Optional[Text1024] = None
    args: Optional[Text4096] = None
    hash: Optional[Text256] = None

class ProcessSchema(BaseModel):
    pid: int
    start_time: Optional[int] = None
    name: Text256 = ""
    path: Optional[Text1024] = None
    args: Optional[Text4096] = None
    hash: Optional[Text256] = None
    parent: Optional[ProcessParentSchema] = None
    children: List[ProcessChildSchema] = Field(default_factory=list)

class NetworkSchema(BaseModel):
    src_ip: Optional[Text256] = None
    dest_ip: constr(max_length=256)
    dest_port: int
    protocol: Text256

class FileSchema(BaseModel):
    path: Text1024
    hash: Optional[Text256] = None
    size: Optional[int] = None
    op: Literal["read", "write"]

class EventSchema(BaseModel):
    alert: AlertSchema
    host: Optional[HostSchema] = None
    user: Optional[UserSchema] = None
    process: Optional[ProcessSchema] = None
    network: List[NetworkSchema] = Field(default_factory=list)
    files: List[FileSchema] = Field(default_factory=list)
    logged_in_hosts: List[constr(max_length=256)] = Field(default_factory=list)
    scanned_hosts: List[constr(max_length=256)] = Field(default_factory=list)

def verify_api_key(request: Request):
    x_api_key = request.headers.get("x-api-key")
    expected_key = os.environ.get("INGEST_API_KEY")
    if not expected_key:
        raise HTTPException(status_code=503, detail="INGEST_API_KEY not configured")
    if not x_api_key or not hmac.compare_digest(x_api_key, expected_key):
        raise HTTPException(status_code=401, detail="Unauthorized")

def enforce_content_length(request: Request):
    content_length = request.headers.get("content-length")
    try:
        if content_length and int(content_length) > 10_000_000:
            raise HTTPException(status_code=413, detail="Payload Too Large")
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid Content-Length")

async def get_validated_payload(request: Request, _auth=Depends(verify_api_key), _len=Depends(enforce_content_length)):
    # By reading JSON manually here, we ensure auth happens BEFORE JSON parsing
    try:
        payload = await request.json()
        return payload
    except Exception:
        raise HTTPException(status_code=422, detail="Invalid JSON body")

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

@router.post("/ingest/events")
def ingest_events(
    payload: dict = Depends(get_validated_payload),
    driver = Depends(get_driver)
):
    events = payload.get("events")
    if not isinstance(events, list):
        return JSONResponse(status_code=422, content={"detail": "payload['events'] must be a list"})

    if len(events) > 500:
        return JSONResponse(status_code=413, content={"detail": "Payload Too Large"})

    accepted = 0
    rejected = []

    with driver.session(database=os.environ.get("NEO4J_DATABASE") or None) as session:
        for i, raw_event in enumerate(events):
            try:
                validated_event = EventSchema(**raw_event)
                load_event(session, validated_event.model_dump(exclude_none=True))
                accepted += 1
            except ValidationError as ve:
                err_msg = "Invalid event"
                for err in ve.errors():
                    if "timestamp must be epoch milliseconds" in err.get("msg", ""):
                        err_msg = "timestamp must be epoch milliseconds"

                # Log only WHERE it failed and WHY (type), never the input value.
                where = [".".join(str(x) for x in err.get("loc", ())) + ":" + err.get("type", "") for err in ve.errors()]
                logger.warning("Validation error on event %s: %s", i, where)
                rejected.append({"index": i, "reason": err_msg})
            except Exception as e:
                logger.error(f"Processing error on event {i}: {e}")
                rejected.append({"index": i, "reason": "Processing error"})

    return {"accepted": accepted, "rejected": rejected}
