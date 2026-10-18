"""
pattern_evaluator.py
Role 1 (Orchestrator) / Role 5 (Backend API) support module.
Confidence scoring + kill-chain detection for matched patterns.
Source: Blueprint v2.0, Section 7.2, with the Section 7.2 flag fixed.

FIXES APPLIED
-------------
1. Naming bug: the original evaluate_patterns(matched_patterns) referenced
   an undefined `matched` inside the function body -- would raise
   NameError the moment it ran, exactly as the blueprint's own flag noted.
2. Type bug: matched_patterns is a list of dicts (each {"id", "name",
   "mitre"}, from pattern_library.PATTERN_LIBRARY / match_patterns()), so
   even with the name fixed, `"P-001" in matched_patterns` would never be
   True -- it checks membership against dict objects, not id strings.
   Fixed by extracting a set of matched IDs first.
3. Generalized the single hardcoded kill-chain triad (P-001 -> P-003 ->
   P-007) into a lookup table of known kill chains, per the Section 7.2
   engineering insight, so CRITICAL escalation isn't limited to the one
   sequence used as the example.
"""

# Known multi-stage attack sequences. Each entry lists the pattern IDs that,
# found together on the same alert investigation, indicate a full attack
# chain rather than an isolated technique. Extend as new chains are found.
KNOWN_KILL_CHAINS = [
    {
        "name": "Phishing -> Credential Dumping -> Exfiltration",
        "stages": ["P-001", "P-003", "P-007"],
    },
    {
        "name": "Remote Execution -> Persistence -> C2 Beaconing",
        "stages": ["P-012", "P-008", "P-004"],
    },
    {
        "name": "Privilege Escalation -> Golden Ticket -> Lateral Movement",
        "stages": ["P-005", "P-010", "P-002"],
    },
]


def evaluate_patterns(matched_patterns: list[dict]) -> tuple[str, bool, str | None]:
    """
    Score confidence and detect kill chains from a list of matched patterns.

    Args:
        matched_patterns: output of pattern_library.match_patterns(), a
            list of {"id", "name", "mitre"} dicts.

    Returns:
        (confidence, kill_chain_detected, kill_chain_name)
        confidence is one of "LOW", "MEDIUM", "HIGH", "CRITICAL".
    """
    matched_ids = {p["id"] for p in matched_patterns}

    confidence = "LOW"
    if len(matched_ids) >= 3:
        confidence = "HIGH"
    elif len(matched_ids) >= 1:
        confidence = "MEDIUM"

    kill_chain_detected = False
    kill_chain_name = None
    for chain in KNOWN_KILL_CHAINS:
        if set(chain["stages"]).issubset(matched_ids):
            kill_chain_detected = True
            kill_chain_name = chain["name"]
            confidence = "CRITICAL"
            break

    return confidence, kill_chain_detected, kill_chain_name
