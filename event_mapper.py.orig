import logging
from typing import Dict, Any, Optional, List, Tuple

from quick_etl import to_epoch_ms

logger = logging.getLogger("event_mapper")

def _get_osquery_candidates(osquery_records: List[Dict[str, Any]], host: str, command: str, alert_time: int) -> List[Dict[str, Any]]:
    candidates = []
    cmd_stripped = command.strip()

    for rec in osquery_records:
        if rec.get("action") not in ("added", "snapshot"):
            continue

        if rec.get("hostIdentifier") != host:
            continue

        cols = rec.get("columns", {})
        osq_cmd = cols.get("cmdline") or cols.get("command")
        if not osq_cmd or osq_cmd.strip() != cmd_stripped:
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

        candidates.append({
            "pid": pid,
            "name": cols.get("name") or (cols.get("path", "").split("/")[-1] if cols.get("path") else None),
            "args": osq_cmd.strip(),
            "osq_time": osq_time
        })

    return candidates

def map_wazuh_alert(raw: Dict[str, Any], osquery_records: List[Dict[str, Any]]) -> Tuple[str, Optional[Dict[str, Any]], Optional[str]]:
    """Returns (status, mapped_event, reason). status is one of: 'mapped', 'noise', 'invalid'."""
    rule = raw.get("rule", {})
    level = rule.get("level")
    if level is None:
        level = 0
    elif isinstance(level, str):
        try:
            level = int(level)
        except ValueError:
            level = 0

    if level < 5:
        return "noise", None, None

    ts_raw = raw.get("timestamp")
    timestamp = to_epoch_ms(ts_raw)

    if timestamp is None or timestamp < 100000000000:
        return "invalid", None, "Missing or invalid timestamp"

    agent = raw.get("agent", {})
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
    if name:
        alert_info["name"] = name

    mitre_raw = rule.get("mitre", {}).get("id")
    if mitre_raw:
        if isinstance(mitre_raw, str):
            alert_info["mitre"] = [mitre_raw]
        elif isinstance(mitre_raw, list) and mitre_raw:
            alert_info["mitre"] = mitre_raw

    event: Dict[str, Any] = {"alert": alert_info}

    agent_name = agent.get("name")
    if agent_name:
        host_info = {"hostname": agent_name}
        ip = agent.get("ip")
        if ip:
            host_info["ip"] = ip
        event["host"] = host_info

    # Process matching
    cmd = raw.get("data", {}).get("win", {}).get("eventdata", {}).get("commandLine") or raw.get("data", {}).get("command")
    attached_info = None

    if cmd and agent_name:
        candidates = _get_osquery_candidates(osquery_records, agent_name, cmd, timestamp)

        distinct_pids = list(set(c["pid"] for c in candidates))

        if len(distinct_pids) == 1:
            pid = distinct_pids[0]
            # Get closest candidate
            closest = min([c for c in candidates if c["pid"] == pid], key=lambda c: abs(c["osq_time"] - timestamp))

            process_info = {"pid": pid, "args": closest["args"]}
            if closest["name"]:
                process_info["name"] = closest["name"]

            event["process"] = process_info

            logger.info("Attached process to alert. alert_id=%s, host=%s, pid=%s, command=%s", alert_id, agent_name, pid, closest["args"])

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
        status, event, attached_info = map_wazuh_alert(raw, osquery_records)
        if status == "invalid":
            invalid.append({"index": i, "reason": attached_info}) # attached_info is reason for invalid
        elif status == "noise":
            noise_dropped += 1
        elif status == "mapped":
            events.append(event)
            if attached_info:
                attached.append(attached_info)

    return {
        "events": events,
        "noise_dropped": noise_dropped,
        "invalid": invalid,
        "attached": attached
    }