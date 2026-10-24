import logging
from typing import Dict, Any, Optional, List, Tuple

from quick_etl import to_epoch_ms

logger = logging.getLogger("event_mapper")

import re

def normalize_host(name: Any) -> str:
    if not isinstance(name, str):
        return ""
    name = name.strip().lower()
    if re.match(r'^\d+\.\d+\.\d+\.\d+$', name):
        return name
    return name.split(".", 1)[0]


WINDOW_MS = 900000  # 900 seconds
MAX_NETWORK = 100   # safety cap on network entries per event
MAX_FILES = 100     # safety cap on file entries per event

_PROTOCOLS = {"6": "TCP", "17": "UDP", "tcp": "TCP", "udp": "UDP"}
_FILE_OPS = {
    "CREATED": "write",
    "UPDATED": "write",
    "MOVED_TO": "write",
    "ACCESSED": "read",
    "OPENED": "read",
}


def _to_int(value: Any) -> Optional[int]:
    """Convert an int or a numeric string to int. bool, floats and other types give None."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value.strip())
        except ValueError:
            return None
    return None


def _clean_str(value: Any) -> Optional[str]:
    """Return a stripped non-empty string, otherwise None."""
    if isinstance(value, str):
        value = value.strip()
        if value:
            return value
    return None


def _split_user(value: Any) -> Optional[Dict[str, str]]:
    """Turn 'DOMAIN\\user' or 'user' into {"username": ..., "domain": ...}. No username means None."""
    text = _clean_str(value)
    if text is None:
        return None
    domain = ""
    username = text
    if "\\" in text:
        domain, _, username = text.partition("\\")
        domain = domain.strip()
        username = username.strip()
    if not username:
        return None
    user: Dict[str, str] = {"username": username}
    if domain:
        user["domain"] = domain
    return user


def _records_for_pid(osquery_records: List[Dict[str, Any]], host: str, pid: int, alert_time: int):
    """Yield (record, columns) for osquery records of the same host, the same pid, inside the time window."""
    norm_host = normalize_host(host)
    if not norm_host:
        return
    for rec in osquery_records:
        if not isinstance(rec, dict):
            continue
        if rec.get("action") not in ("added", "snapshot"):
            continue
        if normalize_host(rec.get("hostIdentifier")) != norm_host:
            continue
        cols = rec.get("columns")
        if not isinstance(cols, dict):
            continue
        if _to_int(cols.get("pid")) != pid:
            continue
        osq_time = to_epoch_ms(rec.get("unixTime"))
        if osq_time is None or abs(osq_time - alert_time) > WINDOW_MS:
            continue
        yield rec, cols


def _get_network(osquery_records: List[Dict[str, Any]], host: str, pid: int, alert_time: int) -> List[Dict[str, Any]]:
    """Network entries from process_open_sockets rows of the matched process only."""
    result: List[Dict[str, Any]] = []
    seen = set()
    for _rec, cols in _records_for_pid(osquery_records, host, pid, alert_time):
        dest_ip = _clean_str(cols.get("remote_address"))
        dest_port = _to_int(cols.get("remote_port"))
        if dest_ip is None or dest_port is None or not (1 <= dest_port <= 65535):
            continue
        proto_raw = cols.get("protocol")
        proto_key = str(proto_raw).strip().lower() if isinstance(proto_raw, (str, int)) and not isinstance(proto_raw, bool) else ""
        protocol = _PROTOCOLS.get(proto_key)
        if protocol is None:
            continue
        entry: Dict[str, Any] = {"dest_ip": dest_ip, "dest_port": dest_port, "protocol": protocol}
        src_ip = _clean_str(cols.get("local_address"))
        if src_ip is not None:
            entry["src_ip"] = src_ip
        key = (dest_ip, dest_port, protocol, src_ip)
        if key in seen:
            continue
        seen.add(key)
        result.append(entry)
        if len(result) >= MAX_NETWORK:
            break
    return result


def _get_files(osquery_records: List[Dict[str, Any]], host: str, pid: int, alert_time: int) -> List[Dict[str, Any]]:
    """File entries only from rows that carry the same pid AND a file action (no pid, no file entry)."""
    result: List[Dict[str, Any]] = []
    seen = set()
    for _rec, cols in _records_for_pid(osquery_records, host, pid, alert_time):
        action = cols.get("action")
        if not isinstance(action, str):
            continue
        op = _FILE_OPS.get(action.strip().upper())
        if op is None:
            continue
        path = _clean_str(cols.get("target_path")) or _clean_str(cols.get("path"))
        if path is None:
            continue
        key = (path, op)
        if key in seen:
            continue
        seen.add(key)
        result.append({"path": path, "op": op})
        if len(result) >= MAX_FILES:
            break
    return result

def _get_osquery_candidates(osquery_records: List[Dict[str, Any]], host: str, command: str, alert_time: int) -> List[Dict[str, Any]]:
    candidates = []
    cmd_stripped = command.strip()
    norm_host = normalize_host(host)
    if not norm_host:
        return candidates

    for rec in osquery_records:
        if not isinstance(rec, dict):
            continue

        if rec.get("action") not in ("added", "snapshot"):
            continue

        if normalize_host(rec.get("hostIdentifier")) != norm_host:
            continue

        cols = rec.get("columns")
        if not isinstance(cols, dict):
            cols = {}

        osq_cmd = cols.get("cmdline") or cols.get("command")
        if not isinstance(osq_cmd, str) or osq_cmd.strip() != cmd_stripped:
            continue

        unix_time = rec.get("unixTime")
        osq_time = to_epoch_ms(unix_time)
        if osq_time is None:
            continue

        if abs(osq_time - alert_time) > 900000: # 900 seconds in ms
            continue

        pid_raw = cols.get("pid")
        if pid_raw is None:
            continue

        try:
            pid = int(pid_raw)
        except (ValueError, TypeError):
            continue

        name_val = cols.get("name")
        if not name_val and isinstance(cols.get("path"), str):
            name_val = cols.get("path").split("/")[-1]

        parent_pid = _to_int(cols.get("parent"))
        if parent_pid is not None and parent_pid <= 0:
            parent_pid = None

        candidates.append({
            "pid": pid,
            "name": name_val,
            "args": osq_cmd.strip(),
            "osq_time": osq_time,
            "parent": parent_pid
        })

    return candidates

def map_wazuh_alert(raw: Dict[str, Any], osquery_records: List[Dict[str, Any]]) -> Tuple[str, Optional[Dict[str, Any]], Optional[str]]:
    """Returns (status, mapped_event, reason). status is one of: 'mapped', 'noise', 'invalid'."""
    rule = raw.get("rule")
    if not isinstance(rule, dict):
        return "invalid", None, "Missing rule"

    level = rule.get("level")
    if level is None:
        level = 0
    elif isinstance(level, bool):
        return "invalid", None, "Invalid level"
    elif isinstance(level, int):
        pass
    elif isinstance(level, float):
        if level.is_integer():
            level = int(level)
        else:
            return "invalid", None, "Invalid level"
    elif isinstance(level, str):
        try:
            f_val = float(level)
            if f_val.is_integer():
                level = int(f_val)
            else:
                return "invalid", None, "Invalid level"
        except ValueError:
            return "invalid", None, "Invalid level"
    else:
        return "invalid", None, "Invalid level"

    if level < 0 or level > 15:
        return "invalid", None, "Level out of range 0-15"
    if level < 5:
        return "noise", None, None

    ts_raw = raw.get("timestamp")
    timestamp = to_epoch_ms(ts_raw)

    if timestamp is None or timestamp < 100000000000:
        return "invalid", None, "Missing or invalid timestamp"

    agent = raw.get("agent")
    if not isinstance(agent, dict):
        agent = {}

    agent_id = agent.get("id")
    rule_id = rule.get("id")

    top_id = raw.get("id")
    if top_id is not None and str(top_id).strip():
        alert_id = f"wazuh-{top_id}"
    else:
        if not agent_id or not rule_id:
            return "invalid", None, "Missing agent.id or rule.id with no top-level id"
        alert_id = f"wazuh-{agent_id}-{rule_id}-{timestamp}"

    if len(alert_id) > 255:
        return "invalid", None, "Generated ID exceeds 255 characters"

    alert_info: Dict[str, Any] = {
        "id": alert_id,
        "level": level,
        "timestamp": timestamp
    }

    name = rule.get("description")
    if isinstance(name, str):
        alert_info["name"] = name

    mitre_obj = rule.get("mitre")
    if not isinstance(mitre_obj, dict):
        mitre_obj = {}

    mitre_raw = mitre_obj.get("id")
    if mitre_raw:
        if isinstance(mitre_raw, str):
            alert_info["mitre"] = [mitre_raw]
        elif isinstance(mitre_raw, list):
            mitre_list = [str(x) for x in mitre_raw if x is not None]
            if mitre_list:
                alert_info["mitre"] = mitre_list

    event: Dict[str, Any] = {"alert": alert_info}

    agent_name = agent.get("name")
    if agent_name:
        host_info = {"hostname": agent_name}
        ip = agent.get("ip")
        if ip:
            host_info["ip"] = ip
        event["host"] = host_info

    # Process matching
    data = raw.get("data")
    if not isinstance(data, dict):
        data = {}

    win = data.get("win")
    if not isinstance(win, dict):
        win = {}

    eventdata = win.get("eventdata")
    if not isinstance(eventdata, dict):
        eventdata = {}

    user = _split_user(eventdata.get("user")) or _split_user(data.get("dstuser"))
    if user:
        event["user"] = user

    cmd = eventdata.get("commandLine") or data.get("command")
    attached_info = None

    if isinstance(cmd, str) and agent_name:
        candidates = _get_osquery_candidates(osquery_records, agent_name, cmd, timestamp)

        if not candidates:
            logger.info("No osquery match for alert. alert_id=%s, host=%s", alert_id, agent_name)
        else:
            distinct_pids = list(set(c["pid"] for c in candidates))

            if len(distinct_pids) == 1:
                pid = distinct_pids[0]
                # Get closest candidate
                closest = min([c for c in candidates if c["pid"] == pid], key=lambda c: abs(c["osq_time"] - timestamp))

                process_info = {"pid": pid, "args": closest["args"]}
                if closest["name"]:
                    process_info["name"] = closest["name"]
                parent_pid = next((c["parent"] for c in sorted(candidates, key=lambda c: abs(c["osq_time"] - timestamp)) if c["pid"] == pid and c["parent"]), None)
                if parent_pid:
                    process_info["parent"] = {"pid": parent_pid}

                event["process"] = process_info

                network = _get_network(osquery_records, agent_name, pid, timestamp)
                if network:
                    event["network"] = network
                files = _get_files(osquery_records, agent_name, pid, timestamp)
                if files:
                    event["files"] = files

                # The command line is not logged on purpose: it can contain secrets.
                logger.info("Attached process to alert. alert_id=%s, host=%s, pid=%s", alert_id, agent_name, pid)

                attached_info = {
                    "alert_id": alert_id,
                    "host": agent_name,
                    "pid": pid,
                    "command": closest["args"]
                }

    return "mapped", event, attached_info

def map_events(wazuh_records: List[Dict[str, Any]], osquery_records: List[Dict[str, Any]]) -> Dict[str, Any]:
    events = []
    invalid = []
    attached = []
    noise_dropped = 0

    for i, raw in enumerate(wazuh_records):
        try:
            if not isinstance(raw, dict):
                invalid.append({"index": i, "reason": "Record is not an object"})
                continue

            status, event, attached_info = map_wazuh_alert(raw, osquery_records)
            if status == "invalid":
                invalid.append({"index": i, "reason": attached_info}) # attached_info is reason for invalid
            elif status == "noise":
                noise_dropped += 1
            elif status == "mapped":
                events.append(event)
                if attached_info:
                    attached.append(attached_info)
        except Exception as e:
            invalid.append({"index": i, "reason": f"Unexpected error: {type(e).__name__}"})

    return {
        "events": events,
        "noise_dropped": noise_dropped,
        "invalid": invalid,
        "attached": attached
    }
