PATTERNS = [
    {
        "id": "P-001",
        "name": "PowerShell Execution",
        "mitre": ["T1059.001"],
        "cypher": """
        MATCH (a:Alert {id: $alert_id})-[:TRIGGERED_BY]->(p:Process)
        WHERE p.name =~ '(?i).*powershell\\.exe'
        RETURN p
        """
    },
    {
        "id": "P-003",
        "name": "SAM/NTDS Read",
        "mitre": ["T1003.002"],
        "cypher": """
        MATCH (a:Alert {id: $alert_id})-[:TRIGGERED_BY]->(p:Process)-[:READS]->(f:File)
        WHERE f.path =~ '(?i).*\\\\config\\\\SAM$' OR f.path =~ '(?i).*NTDS\\.dit$'
        RETURN p, f
        """
    },
    {
        "id": "P-005",
        "name": "Admin Process",
        "mitre": ["T1078.001"],
        "cypher": """
        MATCH (a:Alert {id: $alert_id})-[:TRIGGERED_BY]->(p:Process)
        WHERE p.name CONTAINS 'admin'
        RETURN p
        """
    },
    {
        "id": "P-007",
        "name": "Network Connection",
        "mitre": ["T1071.001"],
        "cypher": """
        MATCH (a:Alert {id: $alert_id})-[:TRIGGERED_BY]->(p:Process)-[:CONNECTED_TO]->(n:Network)
        RETURN p, n
        """
    },
    {
        "id": "P-008",
        "name": "Run Key Modification",
        "mitre": ["T1547.001"],
        "cypher": """
        MATCH (a:Alert {id: $alert_id})-[:TRIGGERED_BY]->(p:Process)-[:WRITES]->(f:File)
        WHERE f.path =~ '(?i).*\\\\CurrentVersion\\\\Run\\\\.*' OR f.path =~ '(?i).*\\\\Startup\\\\.*'
        RETURN p, f
        """
    },
    {
        "id": "P-013",
        "name": "Registry Modification",
        "mitre": ["T1112"],
        "cypher": """
        MATCH (a:Alert {id: $alert_id})-[:TRIGGERED_BY]->(p:Process)
        WHERE p.name = 'reg.exe' OR p.name ENDS WITH '.reg'
        RETURN p
        """
    },
    {
        "id": "P-017",
        "name": "Port Scanning",
        "mitre": ["T1046"],
        "cypher": """
        MATCH (a:Alert {id: $alert_id})-[:TRIGGERED_BY]->(p:Process)-[:CONNECTED_TO]->(n:Network)
        RETURN p, n
        """
    },
    {
        "id": "P-021",
        "name": "Reverse Shell (Unix)",
        "mitre": ["T1059.004"],
        "cypher": """
        MATCH (a:Alert {id: $alert_id})-[:TRIGGERED_BY]->(p:Process)
        WHERE p.args CONTAINS '/dev/tcp/' OR p.args CONTAINS 'nc -e' OR p.args CONTAINS 'netcat -e'
        RETURN p
        """
    },
    {
        "id": "P-022",
        "name": "Sudoers Modification",
        "mitre": ["T1548.003"],
        "cypher": """
        MATCH (a:Alert {id: $alert_id})-[:TRIGGERED_BY]->(p:Process)
        OPTIONAL MATCH (p)-[:WRITES]->(f:File)
        WHERE p.args CONTAINS '/etc/sudoers' OR f.path STARTS WITH '/etc/sudoers'
        RETURN p, f
        """
    }
]

KNOWN_KILL_CHAINS = [
    {
        "id": "KC-001",
        "patterns": ["P-001", "P-003", "P-007"],
        "severity": "CRITICAL"
    },
    {
        "id": "KC-002",
        "patterns": ["P-022", "P-021"],
        "severity": "CRITICAL"
    }
]

def get_pattern(pattern_id):
    for p in PATTERNS:
        if p["id"] == pattern_id:
            return p
    return None

def match_patterns(alert_id, driver):
    matched = []
    with driver.session() as session:
        for pattern in PATTERNS:
            if "cypher" in pattern:
                res = session.run(pattern["cypher"], alert_id=alert_id)
                if res.peek():
                    matched.append(pattern["id"])
    return matched
