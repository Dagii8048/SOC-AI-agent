import pytest
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from graph_queries import to_cytoscape

def test_to_cytoscape_formatting():
    subgraph = {
        "nodes": [
            {"id": "A1", "labels": ["Alert"], "props": {"name": "Test Alert", "level": 10}},
            {"id": "H1", "labels": ["Host"], "props": {"hostname": "srv-01", "os": "Linux"}},
            {"id": "P1", "labels": ["Process"], "props": {"name": "bash", "pid": 123}}
        ],
        "edges": [
            {"from": "A1", "to": "P1", "type": "TRIGGERED_BY"},
            {"from": "P1", "to": "H1", "type": "RUNS_ON"},
            {"from": "A1", "to": "H1", "type": "DETECTED_ON"}
        ]
    }

    cy_graph = to_cytoscape(subgraph)

    assert len(cy_graph["nodes"]) == 3
    assert len(cy_graph["edges"]) == 3

    node_ids = [n["data"]["id"] for n in cy_graph["nodes"]]
    assert "A1" in node_ids
    assert "H1" in node_ids
    assert "P1" in node_ids

    labels = {n["data"]["id"]: n["data"]["label"] for n in cy_graph["nodes"]}
    assert labels["A1"] == "Test Alert"
    assert labels["H1"] == "srv-01"
    assert labels["P1"] == "bash"

    edge_ids = [e["data"]["id"] for e in cy_graph["edges"]]
    assert len(set(edge_ids)) == 3
    assert "A1|TRIGGERED_BY|P1" in edge_ids
    assert "P1|RUNS_ON|H1" in edge_ids
    assert "A1|DETECTED_ON|H1" in edge_ids

    # Validate all source/target exist
    for edge in cy_graph["edges"]:
        assert edge["data"]["source"] in node_ids
        assert edge["data"]["target"] in node_ids
