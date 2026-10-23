import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import pytest
from fastapi.testclient import TestClient
from fastapi import FastAPI
from ingest_router import router, get_driver
from unittest.mock import MagicMock, patch

app = FastAPI()
app.include_router(router)
client = TestClient(app)

def test_missing_env():
    if "INGEST_API_KEY" in os.environ:
        del os.environ["INGEST_API_KEY"]
    resp = client.post("/ingest/events", json={"events": []})
    assert resp.status_code == 503

def test_wrong_key():
    os.environ["INGEST_API_KEY"] = "secret"
    resp = client.post("/ingest/events", json={"events": []}, headers={"x-api-key": "bad"})
    assert resp.status_code == 401

def test_unauth_overrides_body():
    # If not authenticated, we should get 401 before getting a 422 for bad body
    os.environ["INGEST_API_KEY"] = "secret"
    resp = client.post("/ingest/events", data="invalid json format", headers={"x-api-key": "bad"})
    assert resp.status_code == 401

def test_too_large_content_length():
    os.environ["INGEST_API_KEY"] = "secret"
    resp = client.post("/ingest/events", json={"events": []}, headers={"x-api-key": "secret", "content-length": "11000000"})
    assert resp.status_code == 413

def test_bad_payload_events_not_list():
    os.environ["INGEST_API_KEY"] = "secret"
    resp = client.post("/ingest/events", json={"events": "string"}, headers={"x-api-key": "secret"})
    assert resp.status_code == 422

def test_too_many_events():
    os.environ["INGEST_API_KEY"] = "secret"
    resp = client.post("/ingest/events", json={"events": [{}] * 501}, headers={"x-api-key": "secret"})
    assert resp.status_code == 413

@patch('ingest_router.load_event')
def test_partial_rejects(mock_load_event):
    os.environ["INGEST_API_KEY"] = "secret"

    mock_driver = MagicMock()
    app.dependency_overrides[get_driver] = lambda: mock_driver

    # 1 valid, 1 invalid (missing alert id), 1 invalid (bad timestamp)
    events = [
        {"alert": {"id": "1", "timestamp": 1234567890000}},
        {"alert": {"timestamp": 1234567890000}},
        {"alert": {"id": "3", "timestamp": 123}}
    ]
    resp = client.post("/ingest/events", json={"events": events}, headers={"x-api-key": "secret"})

    assert resp.status_code == 200
    data = resp.json()
    assert data["accepted"] == 1
    assert len(data["rejected"]) == 2

    assert data["rejected"][0]["index"] == 1
    assert data["rejected"][0]["reason"] == "Invalid event"

    assert data["rejected"][1]["index"] == 2
    assert data["rejected"][1]["reason"] == "timestamp must be epoch milliseconds"

    app.dependency_overrides.clear()
