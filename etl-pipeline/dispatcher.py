import argparse
import json
import logging
import os
import sys
import time
import urllib.request
import urllib.error
import copy

import event_mapper

logger = logging.getLogger(__name__)

def truncate_text(s, limit):
    if not isinstance(s, str):
        return s
    L = len(s)
    if L <= limit:
        return s

    # We want to replace N characters in the middle with a marker: " ...[truncated N chars]... "
    # N is the number of removed characters.
    # So limit >= len(marker) + head_len + tail_len
    # Actually, L = head_len + N + tail_len
    # Result length = head_len + len(marker) + tail_len <= limit
    # This means len(marker) + N + tail_len + head_len - len(marker) = L
    # We need to find the right N. Since the marker length depends on the number of digits in N,
    # we can compute it iteratively. Usually it takes 1 or 2 iterations.

    N = L - limit + 30 # initial guess for marker length around 30 chars
    while True:
        marker = f" ...[truncated {N} chars]... "
        marker_len = len(marker)
        if marker_len >= limit:
            # If limit is so small it can't even fit the marker, just hard truncate
            return s[:limit]

        head_len = (limit - marker_len) // 2
        tail_len = limit - marker_len - head_len

        actual_N = L - head_len - tail_len
        if actual_N == N:
            break
        N = actual_N

    return s[:head_len] + marker + s[L - tail_len:]

def _apply_trunc(d, key, limit, is_ip=False):
    if not isinstance(d, dict):
        return
    if key in d:
        val = d[key]
        if is_ip and val is not None and not isinstance(val, str):
            val = str(val)
        if isinstance(val, str):
            d[key] = truncate_text(val, limit)

def truncate_event(event):
    e = copy.deepcopy(event)

    if "process" in e and isinstance(e["process"], dict):
        p = e["process"]
        _apply_trunc(p, "args", 4096)
        _apply_trunc(p, "path", 1024)
        _apply_trunc(p, "name", 256)
        _apply_trunc(p, "hash", 256)

        if "parent" in p and isinstance(p["parent"], dict):
            _apply_trunc(p["parent"], "args", 4096)
            _apply_trunc(p["parent"], "path", 1024)
            _apply_trunc(p["parent"], "name", 256)
            _apply_trunc(p["parent"], "hash", 256)

        if "children" in p and isinstance(p["children"], list):
            for child in p["children"]:
                if isinstance(child, dict):
                    _apply_trunc(child, "args", 4096)
                    _apply_trunc(child, "name", 256)

    if "alert" in e and isinstance(e["alert"], dict):
        _apply_trunc(e["alert"], "name", 256)

    if "host" in e and isinstance(e["host"], dict):
        _apply_trunc(e["host"], "hostname", 256)
        _apply_trunc(e["host"], "os", 256)
        _apply_trunc(e["host"], "ip", 256, is_ip=True)

    if "user" in e and isinstance(e["user"], dict):
        _apply_trunc(e["user"], "username", 256)
        _apply_trunc(e["user"], "domain", 256)

    if "files" in e and isinstance(e["files"], list):
        for f in e["files"]:
            _apply_trunc(f, "path", 1024)

    if "network" in e and isinstance(e["network"], list):
        for n in e["network"]:
            _apply_trunc(n, "dest_ip", 256, is_ip=True)
            _apply_trunc(n, "src_ip", 256, is_ip=True)

    return e

def split_batches(events, max_events=500, max_bytes=9_000_000):
    """
    split_batches(events, max_events=500, max_bytes=9_000_000): split by count AND by JSON size
    (len(json.dumps(batch).encode("utf-8"))), keeping order.
    """
    batches = []
    current_batch = []

    for event in events:
        test_batch = current_batch + [event]
        if len(test_batch) > max_events or len(json.dumps(test_batch).encode("utf-8")) > max_bytes:
            if current_batch:
                batches.append(current_batch)
            current_batch = [event]
        else:
            current_batch.append(event)

    if current_batch:
        batches.append(current_batch)

    return batches

def send_batch(url, key, batch, timeout=30):
    """
    send_batch(url, key, batch, timeout=30): POST {"events": batch} with headers Content-Type: application/json
    and X-API-Key: <key> via urllib.request. Returns (status_code, parsed_json_or_None).
    """
    req = urllib.request.Request(
        url,
        data=json.dumps({"events": batch}).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "X-API-Key": key
        },
        method="POST"
    )

    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            status_code = response.getcode()
            body = response.read()
            try:
                parsed_json = json.loads(body)
            except json.JSONDecodeError:
                parsed_json = None
            return (status_code, parsed_json)
    except urllib.error.HTTPError as e:
        status_code = e.code
        body = e.read()
        try:
            parsed_json = json.loads(body)
        except json.JSONDecodeError:
            parsed_json = None
        return (status_code, parsed_json)
    except urllib.error.URLError as e:
        # For network errors/timeouts
        return (0, None)
    except Exception as e:
        return (0, None)

def parse_response(status_code, body):
    if status_code == 200 and body is not None:
        accepted = body.get("accepted")
        rejected = body.get("rejected")
        if isinstance(accepted, int) and isinstance(rejected, list):
            return (accepted, rejected)
        else:
            return (None, None)
    return (0, [])

def dispatch(events, url, key, sleep=time.sleep, log_path=None):
    """
    dispatch(events, url, key, sleep=time.sleep, log_path=...) applies truncate_event to every event,
    then sends, and returns {"batches": n, "sent": n, "accepted": n, "rejected": n, "failed": n}.
    """
    if log_path is None:
        log_path = os.environ.get("REJECTED_LOG_PATH", "rejected_events.jsonl")

    truncated = [truncate_event(e) for e in events]
    batches = split_batches(truncated)

    summary = {
        "batches": len(batches),
        "sent": 0,
        "accepted": 0,
        "rejected": 0,
        "failed": 0
    }

    # Process each batch
    i = 0
    while i < len(batches):
        batch = batches[i]

        retries = 0
        backoffs = [1, 2, 4]

        while retries <= 3:
            status, body = send_batch(url, key, batch)

            if status == 401:
                logger.error("Unauthorized (401): check INGEST_API_KEY")
                return summary

            if status == 413 or status == 422:
                # no retry and NO splitting; count the batch as failed and log only the status code
                summary["failed"] += len(batch)
                summary["sent"] += len(batch)
                logger.error(f"Status {status}")
                break # move to next batch

            if status >= 500 or status == 0: # 5xx or network error
                if retries < 3:
                    sleep(backoffs[retries])
                    retries += 1
                    continue
                else:
                    # no more retries
                    summary["failed"] += len(batch)
                    summary["sent"] += len(batch)
                    logger.error(f"Status {status}")
                    break

            if status == 200:
                summary["sent"] += len(batch)
                accepted, rejected = parse_response(status, body)

                if accepted is None and rejected is None:
                    # treat the batch as failed
                    summary["failed"] += len(batch)
                    logger.error("Status 200 but invalid body format")
                    break

                summary["accepted"] += accepted
                summary["rejected"] += len(rejected)

                if rejected:
                    # Rejected events from the server reply
                    for r in rejected:
                        idx = r.get("index")
                        reason = r.get("reason", "unknown")
                        if isinstance(idx, int) and 0 <= idx < len(batch):
                            logger.info(f"Rejected index {idx}: {reason}")
                            ev = batch[idx]
                            try:
                                with open(log_path, "a") as f:
                                    f.write(json.dumps({"event": ev, "reason": reason}) + "\n")
                            except Exception:
                                logger.error("Could not write rejected log")
                break # move to next batch

            # Any other status
            summary["failed"] += len(batch)
            summary["sent"] += len(batch)
            logger.error(f"Status {status}")
            break

        i += 1

    return summary

def main():
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    parser = argparse.ArgumentParser(description="Dispatch events to ingest API.")
    parser.add_argument("--wazuh", required=True, help="Path to wazuh JSON file.")
    parser.add_argument("--osquery", required=True, help="Path to osquery JSON file.")
    parser.add_argument("--dry-run", action="store_true", help="Run without network or env variables.")
    args = parser.parse_args()

    with open(args.wazuh, 'r') as f:
        wazuh_data = json.load(f)
    with open(args.osquery, 'r') as f:
        osquery_data = json.load(f)

    mapped = event_mapper.map_events(wazuh_data, osquery_data)
    events = mapped.get("events", [])
    noise_dropped = mapped.get("noise_dropped", 0)
    invalid_count = len(mapped.get("invalid", []))

    if args.dry_run:
        # We need to simulate truncation and splitting
        truncated_events = [truncate_event(e) for e in events]
        batches = split_batches(truncated_events)

        print(f"number of events: {len(truncated_events)}")
        print(f"number of batches: {len(batches)}")
        for i, b in enumerate(batches):
            print(f"batch {i} size: {len(b)}")
        print(f"noise_dropped: {noise_dropped}")
        print(f"invalid count: {invalid_count}")

    else:
        url = os.environ.get("INGEST_URL")
        key = os.environ.get("INGEST_API_KEY")
        if not url:
            print("Missing environment variable: INGEST_URL")
            sys.exit(1)
        if not key:
            print("Missing environment variable: INGEST_API_KEY")
            sys.exit(1)

        summary = dispatch(events, url, key)
        print(json.dumps(summary))

if __name__ == "__main__":
    main()
