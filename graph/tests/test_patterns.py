import pytest
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from unittest.mock import MagicMock
from pattern_library import match_patterns, PATTERNS
from pattern_evaluator import evaluate_patterns

def test_pattern_evaluator():
    assert evaluate_patterns([{"id": "P-001"}, {"id": "P-003"}, {"id": "P-007"}]) == ("CRITICAL", True, "Phishing -> Credential Dumping -> Exfiltration")
    assert evaluate_patterns([{"id": "P-022"}, {"id": "P-021"}]) == ("CRITICAL", True, "Linux Privilege Escalation and Reverse Shell")
    assert evaluate_patterns([{"id": "P-001"}]) == ("MEDIUM", False, None)
    assert evaluate_patterns([]) == ("LOW", False, None)
    assert evaluate_patterns([{"id": "P-001"}, {"id": "P-002"}, {"id": "P-003"}]) == ("HIGH", False, None)

def test_all_22_patterns_exist():
    assert len(PATTERNS) == 22
    ids = [p["id"] for p in PATTERNS]
    for i in range(1, 23):
        assert f"P-{i:03}" in ids

    # Original MITRE validation for a few
    p001 = next(p for p in PATTERNS if p["id"] == "P-001")
    assert p001["mitre"] == "T1059.001"

def test_compatibility_replay():
    driver = MagicMock()
    session = driver.session.return_value.__enter__.return_value
    def mock_run(query, alert_id):
        mock_res = MagicMock()
        if "powershell" in query and "SPAWNED" in query: # P-001
            mock_res.peek.return_value = True
        elif "SAM" in query and "READS" in query: # P-003
            mock_res.peek.return_value = True
        else:
            mock_res.peek.return_value = None
        return mock_res
    session.run.side_effect = mock_run

    matched = match_patterns(driver, "123")
    assert isinstance(matched, list)
    assert len(matched) == 2

    ids = [m["id"] for m in matched]
    assert "P-001" in ids
    assert "P-003" in ids

    confidence, kc_detected, kc_name = evaluate_patterns(matched)
    assert confidence == "MEDIUM"
    assert kc_detected is False
    assert kc_name is None
