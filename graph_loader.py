import hashlib
from typing import Dict, Any, List

def _get_severity(level: int) -> str:
    if level < 7:
        return "Low"
    elif level <= 9:
        return "Medium"
    elif level <= 11:
        return "High"
    else:
        return "Critical"

def load_event(session, event: Dict[str, Any]) -> None:
    alert = event.get("alert", {})
    alert_id = alert.get("id")
    if not alert_id:
        return

    level = alert.get("level", 0)
    severity = _get_severity(level)

    # Cap string lengths
    alert_name = str(alert.get("name", ""))[:256]

    # Cypher query with parameters
    query = """
    MERGE (a:Alert {id: $alert_id})
    ON CREATE SET a.level = $level, a.severity = $severity, a.name = $alert_name, a.timestamp = $timestamp
    """

    params = {
        "alert_id": alert_id,
        "level": level,
        "severity": severity,
        "alert_name": alert_name,
        "timestamp": alert.get("timestamp")
    }

    host = event.get("host")
    if host:
        hostname = host.get("hostname")
        if hostname:
            query += """
            MERGE (h:Host {hostname: $hostname})
            ON CREATE SET h.ip = $host_ip, h.os = $host_os
            """
            params.update({
                "hostname": hostname,
                "host_ip": host.get("ip"),
                "host_os": host.get("os")
            })

    user = event.get("user")
    if user:
        username = user.get("username")
        if username:
            query += """
            MERGE (u:User {username: $username})
            ON CREATE SET u.domain = $user_domain, u.admin = $user_admin
            """
            params.update({
                "username": username,
                "user_domain": user.get("domain"),
                "user_admin": user.get("admin")
            })
            if host and hostname:
                query += """
                MERGE (u)-[:LOGGED_IN]->(h)
                """

    process = event.get("process")
    if process and host and hostname:
        pid = process.get("pid")
        start_time = process.get("start_time", alert.get("timestamp"))
        if pid is not None and start_time is not None:
            process_uid = f"{hostname}:{pid}:{start_time}"
            process_name = str(process.get("name", ""))[:256]
            process_path = str(process.get("path", ""))[:1024]
            process_args = str(process.get("args", ""))[:4096]

            query += """
            MERGE (p:Process {process_uid: $process_uid})
            ON CREATE SET p.pid = $pid, p.start_time = $start_time, p.name = $process_name, p.path = $process_path, p.args = $process_args
            MERGE (a)-[:TRIGGERED_BY]->(p)
            MERGE (p)-[:RUNS_ON]->(h)
            """
            params.update({
                "process_uid": process_uid,
                "pid": pid,
                "start_time": start_time,
                "process_name": process_name,
                "process_path": process_path,
                "process_args": process_args
            })
            if user and username:
                query += """
                MERGE (u)-[:OWNS]->(p)
                """

            parent = process.get("parent")
            if parent:
                parent_pid = parent.get("pid")
                parent_start_time = parent.get("start_time", start_time) # fallback
                if parent_pid is not None:
                    parent_uid = f"{hostname}:{parent_pid}:{parent_start_time}"
                    parent_name = str(parent.get("name", ""))[:256]
                    query += """
                    MERGE (pp:Process {process_uid: $parent_uid})
                    ON CREATE SET pp.pid = $parent_pid, pp.start_time = $parent_start_time, pp.name = $parent_name
                    MERGE (pp)-[:SPAWNED]->(p)
                    MERGE (pp)-[:RUNS_ON]->(h)
                    """
                    params.update({
                        "parent_uid": parent_uid,
                        "parent_pid": parent_pid,
                        "parent_start_time": parent_start_time,
                        "parent_name": parent_name
                    })

            networks = event.get("network", [])
            for i, net in enumerate(networks):
                dest_ip = net.get("dest_ip")
                dest_port = net.get("dest_port")
                if dest_ip and dest_port:
                    net_id = f"{dest_ip}:{dest_port}"
                    query += f"""
                    MERGE (n{i}:Network {{id: $net_id_{i}}})
                    ON CREATE SET n{i}.dest_ip = $dest_ip_{i}, n{i}.dest_port = $dest_port_{i}, n{i}.protocol = $protocol_{i}
                    MERGE (p)-[:CONNECTED_TO]->(n{i})
                    """
                    params.update({
                        f"net_id_{i}": net_id,
                        f"dest_ip_{i}": dest_ip,
                        f"dest_port_{i}": dest_port,
                        f"protocol_{i}": net.get("protocol")
                    })

            files = event.get("files", [])
            for i, f in enumerate(files):
                path = f.get("path")
                if path:
                    file_uid = f"{hostname}:{path}"
                    file_path = str(path)[:1024]
                    op = f.get("op")
                    query += f"""
                    MERGE (f{i}:File {{file_uid: $file_uid_{i}}})
                    ON CREATE SET f{i}.path = $file_path_{i}
                    """
                    if op == "read":
                        query += f"MERGE (p)-[:READS]->(f{i})\n"
                    elif op == "write":
                        query += f"MERGE (p)-[:WRITES]->(f{i})\n"
                    params.update({
                        f"file_uid_{i}": file_uid,
                        f"file_path_{i}": file_path
                    })

    # Handling logged in and scanned hosts at the host level, outside process if block.
    if host and hostname:
        logged_in_hosts = event.get("logged_in_hosts", [])
        for i, logged_host in enumerate(logged_in_hosts):
            query += f"""
            MERGE (lh{i}:Host {{hostname: $logged_host_{i}}})
            """
            if user and username:
                query += f"""
                MERGE (u)-[:LOGGED_IN]->(lh{i})
                """
            params[f"logged_host_{i}"] = logged_host

        scanned_hosts = event.get("scanned_hosts", [])
        for i, scanned_host in enumerate(scanned_hosts):
            query += f"""
            MERGE (sh{i}:Host {{hostname: $scanned_host_{i}}})
            MERGE (h)-[:SCANNED]->(sh{i})
            """
            params[f"scanned_host_{i}"] = scanned_host

    session.run(query, **params)
