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

    assert "MERGE (a:Alert {id: $alert_id})" in query
    assert "MERGE (p:Process {process_uid: $process_uid})" in query

    assert kwargs["alert_id"] == "123"
    assert kwargs["process_uid"] == "testhost:100:12345"
