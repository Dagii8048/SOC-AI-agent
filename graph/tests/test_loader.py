import pytest
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from unittest.mock import Mock
from graph_loader import load_event

def test_load_event_executes_query():
    session_mock = Mock()
    event = {
        "alert": {"id": "123", "level": 12, "name": "test"},
        "host": {"hostname": "testhost"},
        "process": {"pid": 100, "start_time": 12345, "name": "test.exe"}
    }
    load_event(session_mock, event)
    assert session_mock.run.called

    args, kwargs = session_mock.run.call_args
    query = args[0]

    # Check that parameters are passed properly
    assert "MERGE (a:Alert {id: $alert_id})" in query
    assert "MERGE (p:Process {process_uid: $process_uid})" in query

    # Check parameter values
    assert kwargs["alert_id"] == "123"
    assert kwargs["process_uid"] == "testhost:100:12345"

    # Assert query parametrization instead of raw strings
    assert "$process_uid" in query
    assert "$alert_id" in query
    assert "123" not in query # No direct injection
    assert "testhost" not in query

def test_loader_detected_on():
    session_mock = Mock()
    event = {
        "alert": {"id": "123", "level": 12, "name": "test", "timestamp": 1234567890000},
        "host": {"hostname": "testhost"}
    }
    load_event(session_mock, event)
    assert session_mock.run.called
    args, kwargs = session_mock.run.call_args
    query = args[0]
    assert "MERGE (a:Alert {id: $alert_id})" in query
    assert "MERGE (h:Host {hostname: $hostname})" in query
    assert "MERGE (a)-[:DETECTED_ON]->(h)" in query
    assert "123" not in query
    assert "testhost" not in query
    assert kwargs["hostname"] == "testhost"

def test_loader_with_process():
    session_mock = Mock()
    event = {
        "alert": {"id": "123", "level": 12, "name": "test"},
        "host": {"hostname": "testhost"},
        "process": {"pid": 100, "start_time": 12345, "name": "test.exe"}
    }
    load_event(session_mock, event)
    args, kwargs = session_mock.run.call_args
    query = args[0]
    assert "MERGE (a)-[:DETECTED_ON]->(h)" in query
    assert "MERGE (a)-[:TRIGGERED_BY]->(p)" in query
    assert "MERGE (p)-[:RUNS_ON]->(h)" in query

def test_length_caps_and_missing_optional():
    session_mock = Mock()
    event = {
        "alert": {"id": "1", "level": 5, "name": "A"*300, "timestamp": 123},
        # No host/process, but with a huge username
        "user": {"username": "B"*300}
    }
    load_event(session_mock, event)
    args, kwargs = session_mock.run.call_args

    # Name is capped to 256
    assert len(kwargs["alert_name"]) == 256
    assert kwargs["username"] == "B"*256
