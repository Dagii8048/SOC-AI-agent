import logging
from typing import Dict, Any, List, Tuple
from .timestamps import to_epoch_ms

logger = logging.getLogger(__name__)

def _get_osquery_candidates(osquery_records: List[Dict[str, Any]], agent_name: str, cmd: str, alert_timestamp: int) -> List[Dict[str, Any]]:
    candidates = []
    for rec in osquery_records:
        if not isinstance(rec, dict):
            continue

        host_ident = rec.get("hostIdentifier")
        if not host_ident or host_ident != agent_name:
            continue

        columns = rec.get("columns")
        if not isinstance(columns, dict):
            columns = {}

        osq_cmd = columns.get("cmdline")
        if not isinstance(osq_cmd, str) or not osq_cmd:
            continue

        if osq_cmd == cmd:
            rec_timestamp = to_epoch_ms(rec.get("unixTime") or rec.get("calendarTime"))
            if rec_timestamp is not None and abs(alert_timestamp - rec_timestamp) <= 5000:
                candidates.append({
                    "pid": columns.get("pid"),
                    "name": columns.get("name"),
                    "args": osq_cmd,
                    "osq_time": rec_timestamp
                })
    return candidates

def map_wazuh_alert(raw: Dict[str, Any], osquery_records: List[Dict[str, Any]]) -> Tuple[str, Dict[str, Any] | None, Any]:
    rule = raw.get("rule")
    if not isinstance(rule, dict):
        return "invalid", None, "Missing rule"

    level_raw = rule.get("level")

    if level_raw is None:
        level = 0
    elif isinstance(level_raw, bool):
        return "invalid", None, "Invalid level"
    elif isinstance(level_raw, int):
        level = level_raw
    elif isinstance(level_raw, float):
        if level_raw.is_integer():
            level = int(level_raw)
        else:
            return "invalid", None, "Invalid level"
    elif isinstance(level_raw, str):
        if level_raw.isdigit() or (level_raw.startswith("-") and level_raw[1:].isdigit()):
            level = int(level_raw)
        else:
            return "invalid", None, "Invalid level"
    else:
        return "invalid", None, "Invalid level"

    if level < 0 or level > 15:
        return "invalid", None, "Level out of range 0-15"

    if level < 5:
        return "noise", None, None

    timestamp = to_epoch_ms(raw.get("timestamp"))
    if timestamp is None or timestamp < 100000000000:
        return "invalid", None, "Missing or invalid timestamp"

    agent = raw.get("agent")
    if not isinstance(agent, dict):
        agent = {}

    agent_id = agent.get("id")
    rule_id = rule.get("id")

    if not agent_id and not rule_id:
        return "invalid", None, "Missing agent.id or rule.id with no top-level id"

    alert_id = raw.get("id")
    if not alert_id:
        # Generate a synthetic ID if missing
        alert_id = f"wazuh-{agent_id or 'none'}-{rule_id or 'none'}-{timestamp}"

    alert_info: Dict[str, Any] = {
        "id": alert_id,
        "level": level,
        "timestamp": timestamp
    }

    name = rule.get("description")
    if isinstance(name, str):
        alert_info["name"] = name

    mitre_raw = rule.get("mitre")
    if not isinstance(mitre_raw, dict):
        mitre_raw = {}

    mitre_id_raw = mitre_raw.get("id")
    if mitre_id_raw is not None:
        if isinstance(mitre_id_raw, str):
            alert_info["mitre"] = [mitre_id_raw]
        elif isinstance(mitre_id_raw, list):
            mitre_list = []
            for item in mitre_id_raw:
                if item is not None:
                    mitre_list.append(str(item))
            if mitre_list:
                alert_info["mitre"] = mitre_list

    event: Dict[str, Any] = {"alert": alert_info}

    agent_name = agent.get("name")

    host_info: Dict[str, str] = {}
    if agent_name:
        host_info["hostname"] = agent_name
    ip = agent.get("ip")
    if ip:
        host_info["ip"] = str(ip)

    if host_info:
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

    cmd = eventdata.get("commandLine") or data.get("command")

    attached_info = None

    if isinstance(cmd, str) and agent_name:
        candidates = _get_osquery_candidates(osquery_records, agent_name, cmd, timestamp)

        distinct_pids = list(set(c["pid"] for c in candidates if c.get("pid") is not None))

        if len(distinct_pids) == 1:
            raw_pid = distinct_pids[0]
            # Get closest candidate
            closest = min([c for c in candidates if c["pid"] == raw_pid], key=lambda c: abs(c["osq_time"] - timestamp))

            process_info = {}
            try:
                process_info["pid"] = int(raw_pid)
            except (ValueError, TypeError):
                pass

            if "args" in closest:
                process_info["args"] = str(closest["args"])
            if closest.get("name"):
                process_info["name"] = str(closest["name"])

            if process_info:
                event["process"] = process_info

                logger.info("Attached process to alert. alert_id=%s, host=%s, pid=%s, command=%s", alert_id, agent_name, raw_pid, closest["args"])

                attached_info = {
                    "alert_id": alert_id,
                    "host": agent_name,
                    "pid": raw_pid,
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
