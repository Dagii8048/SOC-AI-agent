from pattern_library import PATTERNS, KNOWN_KILL_CHAINS
from pattern_evaluator import evaluate_patterns

def test_pattern_mitre_ids():
    for pattern in PATTERNS:
        assert "mitre" in pattern
        for mid in pattern["mitre"]:
            assert mid.startswith("T")

def test_pattern_evaluator():
    assert evaluate_patterns(["P-001", "P-003", "P-007"]) == {"severity": "CRITICAL", "kill_chain": "KC-001"}
    assert evaluate_patterns(["P-022", "P-021"]) == {"severity": "CRITICAL", "kill_chain": "KC-002"}
    assert evaluate_patterns(["P-001"]) == {"severity": "LOW", "kill_chain": None}
