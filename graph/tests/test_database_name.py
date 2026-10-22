import pytest
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from unittest.mock import MagicMock
import graph_queries

def test_database_name_env_var(monkeypatch):
    driver = MagicMock()

    # When NEO4J_DATABASE is set
    monkeypatch.setenv("NEO4J_DATABASE", "custom_aura_db")
    graph_queries.get_alert_subgraph(driver, "123")
    driver.session.assert_called_with(database="custom_aura_db")

    # When NEO4J_DATABASE is not set
    monkeypatch.delenv("NEO4J_DATABASE", raising=False)
    graph_queries.get_alert_subgraph(driver, "123")
    driver.session.assert_called_with(database=None)
