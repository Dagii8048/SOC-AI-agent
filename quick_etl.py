import json
import os
from datetime import datetime
from typing import Dict, Any, Optional, List

from datetime import timezone, timedelta
import re

# --- Timestamp Normalizer ---
def to_epoch_ms(ts_val: Any) -> Optional[int]:
    """Converts either ISO string or unix epoch to integer UTC milliseconds."""
    if ts_val is None or isinstance(ts_val, bool):
        return None

    if isinstance(ts_val, (int, float)):
        try:
            val = float(ts_val)
            if val < 100000000000: # seconds
                return int(val * 1000)
            else: # milliseconds
                return int(val)
        except Exception:
            return None

    if isinstance(ts_val, str):
        ts_val = ts_val.strip()
        if not ts_val:
            return None

        # Try numeric string
        if ts_val.isdigit() or (ts_val.startswith('-') and ts_val[1:].isdigit()):
            try:
                val = float(ts_val)
                if val < 100000000000:
                    return int(val * 1000)
                else:
                    return int(val)
            except Exception:
                pass

        try:
            # Clean up the string to ensure a standard ISO format
            # Replace space with T
            ts_str = ts_val.replace(' ', 'T')

            # Extract fractional seconds
            frac_ms = 0
            if '.' in ts_str:
                parts = ts_str.split('.')
                main_part = parts[0]
                rest = parts[1]

                # Extract digits after dot for ms
                frac_digits = ""
                for c in rest:
                    if c.isdigit():
                        frac_digits += c
                    else:
                        break

                if frac_digits:
                    # Truncate or pad to exactly 3 digits for ms
                    ms_str = (frac_digits + "000")[:3]
                    frac_ms = int(ms_str)
                    ts_str = main_part + rest[len(frac_digits):]
                else:
                    ts_str = main_part + rest

            # Replace 'Z' with +0000
            if ts_str.endswith('Z'):
                ts_str = ts_str[:-1] + '+0000'

            # Adjust timezones like +0300 or +03:00 or -0400 or missing
            tz_offset = timezone.utc

            # Look for + or - at the end
            match = re.search(r'([+-])(\d{2}):?(\d{2})$', ts_str)
            if match:
                sign = 1 if match.group(1) == '+' else -1
                hours = int(match.group(2))
                mins = int(match.group(3))
                tz_offset = timezone(timedelta(hours=sign * hours, minutes=sign * mins))
                ts_str = ts_str[:match.start()]

            # Now we have clean ts_str like "YYYY-MM-DDTHH:MM:SS"
            dt = datetime.strptime(ts_str, "%Y-%m-%dT%H:%M:%S")
            # Make it timezone-aware
            dt = dt.replace(tzinfo=tz_offset)

            # Convert to UTC
            dt_utc = dt.astimezone(timezone.utc)

            # Calculate total seconds from epoch
            epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
            delta = dt_utc - epoch

            total_seconds = int(delta.total_seconds())
            return total_seconds * 1000 + frac_ms

        except Exception:
            return None

    return None

def to_unix_seconds(ts_val: Any) -> int:
    """Converts either ISO string or unix epoch to integer seconds."""
    ms = to_epoch_ms(ts_val)
    if ms is None:
        return 0
    return ms // 1000

# --- Parsers ---
def parse_wazuh_entry(raw: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    rule = raw.get("rule", {})
    if rule.get("level", 0) < 5:
        return None

    agent = raw.get("agent", {})
    host = agent.get("name", "unknown-host")
    cmd = (
        raw.get("data", {}).get("win", {}).get("eventdata", {}).get("commandLine")
        or raw.get("data", {}).get("command")
        or raw.get("full_log", "No details")
    )
    mitre_ids = rule.get("mitre", {}).get("id", [])
    if isinstance(mitre_ids, str):
        mitre_ids = [mitre_ids]

    return {
        "source": "Wazuh Alert",
        "host": host,
        "epoch": to_unix_seconds(raw.get("timestamp")),
        "severity": rule.get("level", 0),
        "summary": rule.get("description", "Security alert"),
        "mitre": mitre_ids,
        "evidence": cmd
    }

def parse_osquery_entry(raw: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    if raw.get("action") not in ["added", "snapshot"]:
        return None

    cols = raw.get("columns", {})
    host = raw.get("hostIdentifier", "unknown-host")
    query = raw.get("name", "system_audit")
    binary = cols.get("path", cols.get("name", "N/A"))
    cmd = cols.get("cmdline", cols.get("command", "N/A"))

    return {
        "source": "osquery Host Event",
        "host": host,
        "epoch": to_unix_seconds(raw.get("unixTime")),
        "severity": 0,
        "summary": f"Process execution audit ({query})",
        "mitre": [],
        "evidence": f"Binary: {binary} | PID: {cols.get('pid')} | Command: {cmd}"
    }

# --- Temporal Correlation Engine ---
def correlate_events(events: List[Dict[str, Any]], window_seconds: int = 900) -> List[Dict[str, Any]]:
    """Groups logs on the same host occurring within a 15-minute window into unified incident stories."""
    # Group by host
    hosts = {}
    for ev in events:
        hosts.setdefault(ev["host"], []).append(ev)

    rag_chunks = []

    for host, host_events in hosts.items():
        # Sort chronologically
        host_events.sort(key=lambda x: x["epoch"])
        
        clusters = []
        current_cluster = []

        for ev in host_events:
            if not current_cluster:
                current_cluster.append(ev)
            else:
                # If event is within sliding window of the cluster start
                if ev["epoch"] - current_cluster[0]["epoch"] <= window_seconds:
                    current_cluster.append(ev)
                else:
                    clusters.append(current_cluster)
                    current_cluster = [ev]
        if current_cluster:
            clusters.append(current_cluster)

        # Build correlated narrative chunks
        for idx, cluster in enumerate(clusters):
            max_sev = max(e["severity"] for e in cluster)
            all_mitre = list({m for e in cluster for m in e["mitre"]})
            
            timeline_lines = []
            for e in cluster:
                timeline_lines.append(f"  - [{e['source']}] {e['summary']} --> {e['evidence']}")

            correlated_narrative = (
                f"INCIDENT CLUSTER on Host '{host}'\n"
                f"Max Severity Level: {max_sev}\n"
                f"Associated MITRE ATT&CK: {', '.join(all_mitre) if all_mitre else 'None'}\n"
                f"Observed Activity Timeline ({len(cluster)} events):\n"
                + "\n".join(timeline_lines)
            )

            rag_chunks.append({
                "chunk_id": f"incident_{host}_{idx}_{cluster[0]['epoch']}",
                "host": host,
                "event_count": len(cluster),
                "max_severity": max_sev,
                "mitre_techniques": all_mitre,
                "rag_document": correlated_narrative
            })

    return rag_chunks

def run_pipeline():
    raw_events: List[Dict[str, Any]] = []

    wazuh_path = "sample_wazuh.json" if os.path.exists("sample_wazuh.json") else "../sample_wazuh.json"
    osquery_path = "sample_osquery.json" if os.path.exists("sample_osquery.json") else "../sample_osquery.json"

    # Ingest Wazuh
    try:
        with open(wazuh_path, "r", encoding="utf-8") as f:
            for item in json.load(f):
                doc = parse_wazuh_entry(item)
                if doc:
                    raw_events.append(doc)
    except FileNotFoundError:
        print("[!] Wazuh file not found")

    # Ingest osquery
    try:
        with open(osquery_path, "r", encoding="utf-8") as f:
            for item in json.load(f):
                doc = parse_osquery_entry(item)
                if doc:
                    raw_events.append(doc)
    except FileNotFoundError:
        print("[!] osquery file not found")

    # Correlate
    correlated_chunks = correlate_events(raw_events, window_seconds=900)

    # Save to disk
    output_file = "correlated_rag_corpus.json"
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(correlated_chunks, f, indent=2)

    print("=" * 60)
    print(" SOC CORRELATION PIPELINE COMPLETE")
    print("=" * 60)
    print(f"[+] Total raw events aggregated: {len(raw_events)}")
    print(f"[+] Correlated incident chunks generated: {len(correlated_chunks)}")
    print(f"[+] Corpus saved to: {output_file}\n")
    print("--- Sample Correlated RAG Chunk for AI Agent ---")
    if correlated_chunks:
        print(correlated_chunks[0]["rag_document"])
    print("=" * 60)

if __name__ == "__main__":
    run_pipeline()