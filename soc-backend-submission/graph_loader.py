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
    alert_id = str(alert.get("id"))[:256] if alert.get("id") else None
    if not alert_id:
        return

    level = alert.get("level", 0)
    severity = _get_severity(level)

    alert_name = str(alert.get("name", ""))[:256]

    query = """
    MERGE (a:Alert {id: $alert_id})
    ON CREATE SET a.level = $level, a.severity = $severity, a.name = $alert_name, a.timestamp = $timestamp, a.mitre = $mitre
    """

    params = {
        "alert_id": alert_id,
        "level": level,
        "severity": severity,
        "alert_name": alert_name,
        "timestamp": alert.get("timestamp"),
        "mitre": alert.get("mitre", [])
    }

    host = event.get("host")
    if host:
        hostname = str(host.get("hostname"))[:256] if host.get("hostname") else None
        if hostname:
            query += """
            MERGE (h:Host {hostname: $hostname})
            ON CREATE SET h.ip = $host_ip, h.os = $host_os
            """
            params.update({
                "hostname": hostname,
                "host_ip": str(host.get("ip"))[:256] if host.get("ip") else None,
                "host_os": str(host.get("os"))[:256] if host.get("os") else None
            })

    user = event.get("user")
    if user:
        username = str(user.get("username"))[:256] if user.get("username") else None
        if username:
            query += """
            MERGE (u:User {username: $username})
            ON CREATE SET u.domain = $user_domain, u.admin = $user_admin, u.failed_logins = $failed_logins, u.last_failed = $last_failed
            ON MATCH SET u.failed_logins = COALESCE($failed_logins, u.failed_logins),
                         u.last_failed = COALESCE($last_failed, u.last_failed)
            """
            params.update({
                "username": username,
                "user_domain": str(user.get("domain"))[:256] if user.get("domain") else None,
                "user_admin": user.get("admin"),
                "failed_logins": user.get("failed_logins"),
                "last_failed": user.get("last_failed")
            })

    process = event.get("process")
    if process and host and hostname:
        pid = process.get("pid")
        start_time = process.get("start_time", alert.get("timestamp"))
        if pid is not None and start_time is not None:
            process_uid = f"{hostname}:{pid}:{start_time}"

            p_name = str(process.get("name", ""))[:256]
            p_path = str(process.get("path", ""))[:1024] if process.get("path") else None
            p_args = str(process.get("args", ""))[:4096] if process.get("args") else None
            p_hash = str(process.get("hash", ""))[:256] if process.get("hash") else None

            query += """
            MERGE (p:Process {process_uid: $process_uid})
            ON CREATE SET p.pid = $pid, p.start_time = $start_time, p.name = $process_name,
                          p.path = $process_path, p.args = $process_args, p.hash = $process_hash
            MERGE (a)-[:TRIGGERED_BY]->(p)
            MERGE (p)-[:RUNS_ON]->(h)
            """
            params.update({
                "process_uid": process_uid,
                "pid": pid,
                "start_time": start_time,
                "process_name": p_name,
                "process_path": p_path,
                "process_args": p_args,
                "process_hash": p_hash
            })
            if user and username:
                query += """
                MERGE (u)-[:OWNS]->(p)
                """

            parent = process.get("parent")
            if parent:
                parent_pid = parent.get("pid")
                parent_start_time = parent.get("start_time", start_time)
                if parent_pid is not None:
                    parent_uid = f"{hostname}:{parent_pid}:{parent_start_time}"

                    pp_name = str(parent.get("name", ""))[:256]
                    pp_path = str(parent.get("path", ""))[:1024] if parent.get("path") else None
                    pp_args = str(parent.get("args", ""))[:4096] if parent.get("args") else None
                    pp_hash = str(parent.get("hash", ""))[:256] if parent.get("hash") else None

                    query += """
                    MERGE (pp:Process {process_uid: $parent_uid})
                    ON CREATE SET pp.pid = $parent_pid, pp.start_time = $parent_start_time,
                                  pp.name = $parent_name, pp.path = $parent_path,
                                  pp.args = $parent_args, pp.hash = $parent_hash
                    MERGE (pp)-[:SPAWNED]->(p)
                    MERGE (pp)-[:RUNS_ON]->(h)
                    """
                    params.update({
                        "parent_uid": parent_uid,
                        "parent_pid": parent_pid,
                        "parent_start_time": parent_start_time,
                        "parent_name": pp_name,
                        "parent_path": pp_path,
                        "parent_args": pp_args,
                        "parent_hash": pp_hash
                    })

            children = process.get("children", [])
            for i, child in enumerate(children):
                c_pid = child.get("pid")
                c_start = child.get("start_time", start_time)
                if c_pid is not None:
                    c_uid = f"{hostname}:{c_pid}:{c_start}"

                    c_name = str(child.get("name", ""))[:256]
                    c_args = str(child.get("args", ""))[:4096] if child.get("args") else None

                    query += f"""
                    MERGE (cp{i}:Process {{process_uid: $child_uid_{i}}})
                    ON CREATE SET cp{i}.pid = $child_pid_{i}, cp{i}.start_time = $child_start_{i},
                                  cp{i}.name = $child_name_{i}, cp{i}.args = $child_args_{i}
                    MERGE (p)-[:SPAWNED]->(cp{i})
                    MERGE (cp{i})-[:RUNS_ON]->(h)
                    """
                    params.update({
                        f"child_uid_{i}": c_uid,
                        f"child_pid_{i}": c_pid,
                        f"child_start_{i}": c_start,
                        f"child_name_{i}": c_name,
                        f"child_args_{i}": c_args
                    })

            networks = event.get("network", [])
            for i, net in enumerate(networks):
                dest_ip = str(net.get("dest_ip"))[:256] if net.get("dest_ip") else None
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
                        f"protocol_{i}": str(net.get("protocol"))[:256] if net.get("protocol") else None
                    })

            files = event.get("files", [])
            for i, f in enumerate(files):
                path = f.get("path")
                if path:
                    file_uid = f"{hostname}:{path}"
                    f_path = str(path)[:1024]
                    op = f.get("op")
                    query += f"""
                    MERGE (f{i}:File {{file_uid: $file_uid_{i}}})
                    ON CREATE SET f{i}.path = $file_path_{i}, f{i}.hash = $file_hash_{i}, f{i}.size = $file_size_{i}
                    """
                    if op == "read":
                        query += f"MERGE (p)-[:READS]->(f{i})\n"
                    elif op == "write":
                        query += f"MERGE (p)-[:WRITES]->(f{i})\n"
                    params.update({
                        f"file_uid_{i}": file_uid,
                        f"file_path_{i}": f_path,
                        f"file_hash_{i}": str(f.get("hash"))[:256] if f.get("hash") else None,
                        f"file_size_{i}": f.get("size")
                    })

    if host and hostname:
        logged_in_hosts = event.get("logged_in_hosts", [])
        for i, logged_host in enumerate(logged_in_hosts):
            logged_host = str(logged_host)[:256]
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
            scanned_host = str(scanned_host)[:256]
            query += f"""
            MERGE (sh{i}:Host {{hostname: $scanned_host_{i}}})
            MERGE (h)-[:SCANNED]->(sh{i})
            """
            params[f"scanned_host_{i}"] = scanned_host

    session.run(query, **params)
