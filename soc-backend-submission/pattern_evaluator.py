KNOWN_KILL_CHAINS = [
    {
        "name": "Discovery and Exfiltration",
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
    {
        "name": "Linux Privilege Escalation and Reverse Shell",
        "stages": ["P-022", "P-021"],
    },
]

def evaluate_patterns(matched_patterns: list[dict]) -> tuple[str, bool, str | None]:
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
