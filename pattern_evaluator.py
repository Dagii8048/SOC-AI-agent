from pattern_library import KNOWN_KILL_CHAINS

def evaluate_patterns(patterns):
    for kc in KNOWN_KILL_CHAINS:
        if all(p in patterns for p in kc["patterns"]):
            return {"severity": kc["severity"], "kill_chain": kc["id"]}
    return {"severity": "LOW", "kill_chain": None}

def correlate_host_alerts(driver, alert_id, window_ms=1800000):
    # Detect via RUNS_ON as well
    query = """
    MATCH (a:Alert {id: $alert_id})-[:TRIGGERED_BY]->(:Process)-[:RUNS_ON]->(h:Host)
    MATCH (other:Alert)-[:TRIGGERED_BY]->(:Process)-[:RUNS_ON]->(h)
    WHERE other.id <> $alert_id
      AND abs(other.timestamp - a.timestamp) <= $window_ms
    RETURN collect(other.id) AS correlated_ids
    """
    from pattern_library import match_patterns
    with driver.session() as session:
        res = session.run(query, alert_id=alert_id, window_ms=window_ms)
        record = res.single()
        if not record or not record.get("correlated_ids"):
            # Try falling back to detecting via DETECTED_ON (if they were directly associated)
            query2 = """
            MATCH (a:Alert {id: $alert_id})-[:DETECTED_ON]->(h:Host)
            MATCH (other:Alert)-[:DETECTED_ON]->(h)
            WHERE other.id <> $alert_id
              AND abs(other.timestamp - a.timestamp) <= $window_ms
            RETURN collect(other.id) AS correlated_ids
            """
            res = session.run(query2, alert_id=alert_id, window_ms=window_ms)
            record = res.single()

        if not record:
            return evaluate_patterns(match_patterns(alert_id, driver))

        all_ids = record["correlated_ids"] + [alert_id]
        all_patterns = set()
        for i in all_ids:
            all_patterns.update(match_patterns(i, driver))

        return evaluate_patterns(list(all_patterns))
