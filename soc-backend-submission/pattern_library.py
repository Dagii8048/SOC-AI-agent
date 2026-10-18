"""
pattern_library.py
Role 2 (Graph Engineer, Amir) — Week 1 Deliverable
20 hardcoded Cypher patterns mapped to MITRE ATT&CK techniques.
Source: Blueprint v2.0, Section 5.1 / 5.2, with the Section 5.2 flag fixed.

FIXES APPLIED
-------------
1. Alert binding: every pattern now starts from
       MATCH (a:Alert {id: $alert_id})-[:TRIGGERED_BY]->(p:Process)
   The original match_patterns() concatenated a raw
       WHERE a.id = '{alert_id}'
   onto every query string, but several patterns (old P-002, P-009, P-018)
   had no `a` variable in scope at all, so that clause failed to bind and
   those patterns silently returned nothing. Every pattern below is
   rewritten to genuinely anchor on the alert's triggering process.

2. Parameterization: $alert_id is passed as a Neo4j driver parameter, never
   string-interpolated into the query. This closes the Cypher-injection risk
   the same flag called out (raw alert data landing directly in query text).

3. Schema-consistency fixes: three original patterns chained relationship
   types that Section 4.2 never defines --
     - old P-002 used (Host)-[:CONNECTED_TO]->(Host)
     - old P-007 used (File)-[:CONNECTED_TO]->(Network)
     - old P-017 used (Host)-[:CONNECTED_TO]->(Network)
   CONNECTED_TO is defined only as Process->Network. Rewritten below to
   route through the Process node consistent with the schema; flag for the
   team if the original intent was actually different (e.g. a real
   Host-to-Host or Host-to-Network edge type may need to be added to the
   schema rather than reusing CONNECTED_TO).

SCHEMA GAPS (see neo4j_schema_setup.cypher footer for the full note)
---------------------------------------------------------------------
Process.args, File.extension, User.failed_logins, and User.last_failed are
used below but aren't in the Section 4.1 property tables yet -- add them to
the ETL's node-creation step before these patterns will return real matches.
"""
from typing import Any

PATTERNS: list[dict[str, str]] = [
    {
        "id": "P-001",
        "name": "Phishing Payload",
        "mitre": "T1059.001",
        "cypher": """
            MATCH (a:Alert {id: $alert_id})-[:TRIGGERED_BY]->(p:Process)
            MATCH (u:User)-[:OWNS]->(p)-[:SPAWNED]->(c:Process)
            WHERE c.name CONTAINS "powershell"
            RETURN a, u, p, c
        """,
    },
    {
        "id": "P-002",
        "name": "Lateral Movement",
        "mitre": "T1021",
        "cypher": """
            MATCH (a:Alert {id: $alert_id})-[:TRIGGERED_BY]->(p:Process)-[:RUNS_ON]->(h1:Host)
            MATCH (u:User)-[:LOGGED_IN]->(h1)
            MATCH (u)-[:LOGGED_IN]->(h2:Host)
            WHERE h2.hostname <> h1.hostname
            RETURN a, u, h1, h2
        """,
    },
    {
        "id": "P-003",
        "name": "Credential Dumping",
        "mitre": "T1003.002",
        "cypher": r"""
            MATCH (a:Alert {id: $alert_id})-[:TRIGGERED_BY]->(p:Process)
            MATCH (p)-[:READS]->(f:File)
            WHERE f.path =~ '(?i).*\\\\config\\\\SAM$' OR f.path =~ '(?i).*\\\\NTDS\\\\ntds\\.dit$'
            RETURN a, p, f
        """,
    },
    {
        "id": "P-004",
        "name": "C2 Beaconing",
        "mitre": "T1071.001",
        "cypher": """
            MATCH (a:Alert {id: $alert_id})-[:TRIGGERED_BY]->(p:Process)
            MATCH (p)-[:CONNECTED_TO]->(n:Network)
            WHERE n.dest_port IN [443, 80, 53] AND NOT n.dest_ip STARTS WITH "192.168."
            RETURN a, p, n
        """,
    },
    {
        "id": "P-005",
        "name": "Privilege Escalation",
        "mitre": "T1068",
        "cypher": """
            MATCH (a:Alert {id: $alert_id})-[:TRIGGERED_BY]->(p:Process)
            MATCH (u:User {admin: false})-[:OWNS]->(p)-[:SPAWNED]->(c:Process)
            WHERE c.name CONTAINS "admin"
            RETURN a, u, p, c
        """,
    },
    {
        "id": "P-006",
        "name": "Ransomware Behavior",
        "mitre": "T1486",
        "cypher": """
            MATCH (a:Alert {id: $alert_id})-[:TRIGGERED_BY]->(p:Process)
            MATCH (p)-[:WRITES]->(f:File)
            WHERE f.extension IN ['.encrypted', '.locked']
            RETURN a, p, f
        """,
    },
    {
        "id": "P-007",
        "name": "Data Exfiltration",
        "mitre": "T1048",
        "cypher": """
            MATCH (a:Alert {id: $alert_id})-[:TRIGGERED_BY]->(p:Process)
            MATCH (p)-[:READS]->(f:File)
            MATCH (p)-[:CONNECTED_TO]->(n:Network)
            RETURN a, p, f, n
        """,
    },
    {
        "id": "P-008",
        "name": "Persistence Mechanism",
        "mitre": "T1547",
        "cypher": r"""
            MATCH (a:Alert {id: $alert_id})-[:TRIGGERED_BY]->(p:Process)
            MATCH (p)-[:WRITES]->(f:File)
            WHERE f.path =~ '(?i).*\\\\CurrentVersion\\\\Run\\\\.*' OR f.path =~ '(?i).*\\\\Startup\\\\.*'
            RETURN a, p, f
        """,
    },
    {
        "id": "P-009",
        "name": "Network Reconnaissance",
        "mitre": "T1046",
        "cypher": """
            MATCH (a:Alert {id: $alert_id})-[:TRIGGERED_BY]->(p:Process)-[:RUNS_ON]->(h:Host)
            MATCH (h)-[:SCANNED]->(h2:Host)
            RETURN a, h, h2
        """,
    },
    {
        "id": "P-010",
        "name": "Golden Ticket Attack",
        "mitre": "T1558.001",
        "cypher": """
            MATCH (a:Alert {id: $alert_id})-[:TRIGGERED_BY]->(p:Process)
            MATCH (u:User)-[:OWNS]->(p)
            WHERE p.name CONTAINS "mimikatz" AND p.args CONTAINS "krbtgt"
            RETURN a, u, p
        """,
    },
    {
        "id": "P-011",
        "name": "Kerberoasting",
        "mitre": "T1558.003",
        "cypher": """
            MATCH (a:Alert {id: $alert_id})-[:TRIGGERED_BY]->(p:Process)
            WHERE p.name CONTAINS "GetUserSPNs" OR p.args CONTAINS "kerberoast"
            RETURN a, p
        """,
    },
    {
        "id": "P-012",
        "name": "Remote Execution",
        "mitre": "T1569.002",
        "cypher": """
            MATCH (a:Alert {id: $alert_id})-[:TRIGGERED_BY]->(p:Process)
            MATCH (p)-[:SPAWNED]->(c:Process)
            WHERE c.name CONTAINS "wmic" OR c.name CONTAINS "psexec"
            RETURN a, p, c
        """,
    },
    {
        "id": "P-013",
        "name": "Registry Modification",
        "mitre": "T1112",
        "cypher": """
            MATCH (a:Alert {id: $alert_id})-[:TRIGGERED_BY]->(p:Process)
            MATCH (p)-[:WRITES]->(f:File)
            WHERE f.path CONTAINS "reg.exe" OR f.path CONTAINS ".reg"
            RETURN a, p, f
        """,
    },
    {
        "id": "P-014",
        "name": "Scheduled Task Creation",
        "mitre": "T1053.005",
        "cypher": """
            MATCH (a:Alert {id: $alert_id})-[:TRIGGERED_BY]->(p:Process)
            MATCH (p)-[:WRITES]->(f:File)
            WHERE f.path CONTAINS "schtasks"
            RETURN a, p, f
        """,
    },
    {
        "id": "P-015",
        "name": "Service Creation",
        "mitre": "T1543.003",
        "cypher": """
            MATCH (a:Alert {id: $alert_id})-[:TRIGGERED_BY]->(p:Process)
            MATCH (p)-[:SPAWNED]->(c:Process)
            WHERE c.name CONTAINS "sc.exe" OR c.args CONTAINS "create"
            RETURN a, p, c
        """,
    },
    {
        "id": "P-016",
        "name": "PowerShell Download Cradle",
        "mitre": "T1059.001",
        "cypher": """
            MATCH (a:Alert {id: $alert_id})-[:TRIGGERED_BY]->(p:Process)
            WHERE p.name CONTAINS "powershell"
              AND (p.args CONTAINS "Invoke-WebRequest" OR p.args CONTAINS "DownloadString")
            RETURN a, p
        """,
    },
    {
        "id": "P-017",
        "name": "Port Scanning",
        "mitre": "T1046",
        "cypher": """
            MATCH (a:Alert {id: $alert_id})-[:TRIGGERED_BY]->(p:Process)
            MATCH (p)-[:CONNECTED_TO]->(n:Network)
            WHERE n.dest_port IN [22, 23, 80, 443, 445, 3389] AND n.dest_ip <> "127.0.0.1"
            RETURN a, p, n
        """,
    },
    {
        "id": "P-018",
        "name": "Password Spraying",
        "mitre": "T1110.003",
        "cypher": """
            MATCH (a:Alert {id: $alert_id})-[:TRIGGERED_BY]->(p:Process)
            MATCH (u:User)-[:OWNS]->(p)
            WHERE u.failed_logins > 10 AND u.last_failed > (timestamp() - 3600000)
            RETURN a, u
        """,
    },
    {
        "id": "P-019",
        "name": "Supply Chain Compromise",
        "mitre": "T1195",
        "cypher": """
            MATCH (a:Alert {id: $alert_id})-[:TRIGGERED_BY]->(p:Process)
            MATCH (p)-[:READS]->(f:File)
            WHERE f.path CONTAINS "compromised-update"
            RETURN a, p, f
        """,
    },
    {
        "id": "P-020",
        "name": "LLMNR/NBT-NS Spoofing",
        "mitre": "T1557.001",
        "cypher": """
            MATCH (a:Alert {id: $alert_id})-[:TRIGGERED_BY]->(p:Process)
            MATCH (p)-[:CONNECTED_TO]->(n:Network)
            WHERE n.protocol IN ["LLMNR", "NBTNS"] AND n.src_ip <> n.dest_ip
            RETURN a, p, n
        """,
    },
    {
        "id": "P-021",
        "name": "Reverse Shell (Unix)",
        "mitre": "T1059.004",
        "cypher": """
            MATCH (a:Alert {id: $alert_id})-[:TRIGGERED_BY]->(p:Process)
            WHERE p.args CONTAINS '/dev/tcp/' OR p.args CONTAINS 'nc -e' OR p.args CONTAINS 'netcat -e'
            RETURN a, p
        """,
    },
    {
        "id": "P-022",
        "name": "Sudoers Modification",
        "mitre": "T1548.003",
        "cypher": """
            MATCH (a:Alert {id: $alert_id})-[:TRIGGERED_BY]->(p:Process)
            OPTIONAL MATCH (p)-[:WRITES]->(f:File)
            WITH a, p, f
            WHERE p.args CONTAINS '/etc/sudoers' OR (f IS NOT NULL AND f.path STARTS WITH '/etc/sudoers')
            RETURN a, p, f
        """,
    },
]


def match_patterns(driver: Any, alert_id: str) -> list[dict[str, str]]:
    matched = []
    with driver.session() as session:
        for pattern in PATTERNS:
            result = session.run(pattern["cypher"], alert_id=alert_id)
            if result.peek() is not None:
                matched.append({k: v for k, v in pattern.items() if k != "cypher"})
    return matched

PATTERN_LIBRARY = PATTERNS
