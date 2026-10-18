from pattern_library import match_patterns
from pattern_evaluator import evaluate_patterns

def get_alert_subgraph(driver, alert_id):
    # Retrieve the alert and its immediate connections up to 3 hops away,
    # but do NOT traverse THROUGH Host or User nodes beyond 1 hop.
    # This prevents the subgraph from exploding by connecting unrelated processes that happen to share a host or user.
    query = """
    MATCH p=(a:Alert {id: $alert_id})-[*1..3]-(n)
    WHERE ALL(r IN relationships(p) WHERE type(r) IN ['TRIGGERED_BY', 'OWNS', 'SPAWNED', 'RUNS_ON', 'CONNECTED_TO', 'READS', 'WRITES'])
      AND NONE(x IN nodes(p)[1..-1] WHERE 'Host' IN labels(x) OR 'User' IN labels(x))
    RETURN nodes(p) AS nodes, relationships(p) AS edges
    LIMIT 200
    """
    with driver.session() as session:
        result = session.run(query, alert_id=alert_id)
        nodes = {}
        edges = []

        def get_domain_id(node):
            labels = list(node.labels)
            props = dict(node)
            if "Alert" in labels and "id" in props: return props["id"]
            if "Process" in labels and "process_uid" in props: return props["process_uid"]
            if "Host" in labels and "hostname" in props: return props["hostname"]
            if "User" in labels and "username" in props: return props["username"]
            if "File" in labels and "file_uid" in props: return props["file_uid"]
            if "Network" in labels and "id" in props: return props["id"]
            return node.element_id

        has_record = False

        for record in result:
            has_record = True
            for node in record["nodes"]:
                domain_id = get_domain_id(node)
                nodes[domain_id] = {"id": domain_id, "labels": list(node.labels), "props": dict(node)}
            for edge in record["edges"]:
                from_id = get_domain_id(edge.start_node)
                to_id = get_domain_id(edge.end_node)
                edge_obj = {"from": from_id, "to": to_id, "type": edge.type}
                if edge_obj not in edges:
                    edges.append(edge_obj)

        if not has_record:
            res2 = session.run("MATCH (a:Alert {id: $alert_id}) RETURN a", alert_id=alert_id)
            for rec in res2:
                has_record = True
                domain_id = get_domain_id(rec["a"])
                nodes[domain_id] = {"id": domain_id, "labels": list(rec["a"].labels), "props": dict(rec["a"])}

        return {"nodes": list(nodes.values()), "edges": edges}

def investigate_alert(driver, alert_id):
    subgraph = get_alert_subgraph(driver, alert_id)
    if not subgraph["nodes"]:
        return {"found": False, "confidence": "not-found", "matched_patterns": [], "kill_chain_detected": False, "kill_chain_name": None}

    matched = match_patterns(driver, alert_id)
    confidence, kc_detected, kc_name = evaluate_patterns(matched)

    return {
        "found": True,
        "confidence": confidence,
        "matched_patterns": matched,
        "kill_chain_detected": kc_detected,
        "kill_chain_name": kc_name
    }

def correlate_host_alerts(driver, alert_id, window_ms=1800000):
    query = """
    MATCH (a:Alert {id: $alert_id})-[:TRIGGERED_BY]->(:Process)-[:RUNS_ON]->(h:Host)
    MATCH (other:Alert)-[:TRIGGERED_BY]->(:Process)-[:RUNS_ON]->(h)
    WHERE other.id <> $alert_id
      AND abs(other.timestamp - a.timestamp) <= $window_ms
    RETURN collect(other.id) AS correlated_ids
    """
    with driver.session() as session:
        res = session.run(query, alert_id=alert_id, window_ms=window_ms)
        record = res.single()

        all_matched_patterns = []
        if record and record.get("correlated_ids"):
            all_ids = record["correlated_ids"] + [alert_id]
            seen_p_ids = set()
            for i in all_ids:
                matched = match_patterns(driver, i)
                for m in matched:
                    if m["id"] not in seen_p_ids:
                        seen_p_ids.add(m["id"])
                        all_matched_patterns.append(m)
        else:
            all_matched_patterns = match_patterns(driver, alert_id)

        confidence, kc_detected, kc_name = evaluate_patterns(all_matched_patterns)
        return {"severity": confidence, "kill_chain": kc_name}
