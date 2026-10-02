import json
import os
from datetime import datetime
from typing import Dict, Any, Optional, List

# --- Timestamp Normalizer ---
def to_unix_seconds(ts_val: Any) -> int:
    """Converts either ISO string or unix epoch to integer seconds."""
    if isinstance(ts_val, (int, float)):
        return int(ts_val)
    if isinstance(ts_val, str):
        try:
            # Handle ISO formats like "2026-10-02T08:15:30.120+0000"
            clean_ts = ts_val.split(".")[0].replace("Z", "")
            dt = datetime.strptime(clean_ts, "%Y-%m-%dT%H:%M:%S")
            return int(dt.timestamp())
        except Exception:
            return 0
    return 0

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