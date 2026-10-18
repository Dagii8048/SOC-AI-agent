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

def test_too_large_content_length():
    os.environ["INGEST_API_KEY"] = "secret"
    resp = client.post("/ingest/events", json={"events": []}, headers={"x-api-key": "secret", "content-length": "11000000"})
    assert resp.status_code == 413

@patch('ingest_router.load_event')
def test_success_with_driver(mock_load_event):
    os.environ["INGEST_API_KEY"] = "secret"

    mock_driver = MagicMock()
    app.dependency_overrides[get_driver] = lambda: mock_driver

    evt = {"alert": {"id": "1", "timestamp": 123}, "process": {"pid": 1, "start_time": 123}}
    resp = client.post("/ingest/events", json={"events": [evt]}, headers={"x-api-key": "secret"})

    assert resp.status_code == 200
    assert resp.json()["accepted"] == 1
    assert mock_load_event.called

    app.dependency_overrides.clear()
