import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from unittest.mock import patch

import pytest
from fastapi import HTTPException

import graph_routes


class FakeSession:
    def __init__(self, rows, calls):
        self._rows = rows
        self._calls = calls

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def run(self, query, **params):
        self._calls.append((query, params))
        return self._rows


class FakeDriver:
    def __init__(self, rows=()):
        self.rows = list(rows)
        self.calls = []
        self.database = "unset"

    def session(self, database=None):
        self.database = database
        return FakeSession(self.rows, self.calls)


def test_list_alerts_maps_rows_and_fills_defaults():
    driver = FakeDriver([
        {"id": "A1", "name": "Reverse shell", "severity": "High", "level": 12,
         "timestamp": 1790000000000, "hostname": "web-01"},
        {"id": "A2", "name": None, "severity": None, "level": 3,
         "timestamp": 1789000000000, "hostname": None},
    ])
    alerts = graph_routes.list_alerts(driver, limit=5)

    assert alerts[0] == {"id": "A1", "name": "Reverse shell", "severity": "High",
                         "level": 12, "timestamp": 1790000000000, "hostname": "web-01"}
    assert alerts[1]["name"] == "Unknown alert"
    assert alerts[1]["severity"] == "Low"
    assert alerts[1]["hostname"] is None
    assert driver.calls[0][1] == {"limit": 5}


def test_list_alerts_uses_database_from_env():
    driver = FakeDriver()
    with patch.dict(os.environ, {"NEO4J_DATABASE": "my_aura_db"}):
        graph_routes.list_alerts(driver)
    assert driver.database == "my_aura_db"


def test_alert_graph_returns_cytoscape_nodes_and_edges():
    subgraph = {
        "nodes": [
            {"id": "A1", "labels": ["Alert"], "props": {"name": "Reverse shell"}},
            {"id": "H1", "labels": ["Host"], "props": {"hostname": "web-01"}},
        ],
        "edges": [{"from": "A1", "to": "H1", "type": "DETECTED_ON"}],
    }
    with patch.object(graph_routes, "get_alert_subgraph", return_value=subgraph):
        out = graph_routes.alert_graph(object(), "A1")

    assert [n["data"]["id"] for n in out["nodes"]] == ["A1", "H1"]
    assert out["nodes"][0]["data"]["label"] == "Reverse shell"
    assert out["nodes"][0]["data"]["type"] == "Alert"
    assert out["edges"][0]["data"] == {
        "id": "A1|DETECTED_ON|H1", "source": "A1", "target": "H1", "type": "DETECTED_ON",
    }


def test_alert_graph_unknown_alert_is_404():
    with patch.object(graph_routes, "get_alert_subgraph", return_value={"nodes": [], "edges": []}):
        with pytest.raises(HTTPException) as info:
            graph_routes.alert_graph(object(), "NOPE")
    assert info.value.status_code == 404
