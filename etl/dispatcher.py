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

def truncate_event(event):
    """
    truncate_event(event) returns a COPY (input must not change) with:
    process.args cut to 4096 characters; alert.name, host.hostname and process.name cut to 256;
    host.ip converted to str if present and not a str. Missing keys stay missing.
    """
    e = copy.deepcopy(event)

    if "process" in e:
        if "args" in e["process"] and isinstance(e["process"]["args"], str):
            e["process"]["args"] = e["process"]["args"][:4096]
        if "name" in e["process"] and isinstance(e["process"]["name"], str):
            e["process"]["name"] = e["process"]["name"][:256]

    if "alert" in e:
        if "name" in e["alert"] and isinstance(e["alert"]["name"], str):
            e["alert"]["name"] = e["alert"]["name"][:256]

    if "host" in e:
        if "hostname" in e["host"] and isinstance(e["host"]["hostname"], str):
            e["host"]["hostname"] = e["host"]["hostname"][:256]
        if "ip" in e["host"] and not isinstance(e["host"]["ip"], str):
            e["host"]["ip"] = str(e["host"]["ip"])

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
    """
    ASSUMPTION - confirm with Amir
    """
    if status_code == 200 and body is not None:
        accepted = body.get("accepted", [])
        rejected = body.get("rejected", [])
        return (accepted, rejected)
    return ([], [])

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

            if status == 413:
                # split in half and process
                half = len(batch) // 2
                if half > 0:
                    batches.insert(i + 1, batch[half:])
                    batch = batch[:half]
                    batches[i] = batch
                    # try again this half without incrementing retries, it's a new sub-batch
                    continue
                else:
                    # single event too large
                    for event in batch:
                        try:
                            with open(log_path, "a") as f:
                                f.write(json.dumps({"event": event, "reason": "413"}) + "\n")
                        except Exception:
                            pass
                    summary["rejected"] += len(batch)
                    summary["sent"] += len(batch)
                    break

            if status == 422:
                # whole batch rejected
                for event in batch:
                    try:
                        with open(log_path, "a") as f:
                            f.write(json.dumps({"event": event, "reason": "422"}) + "\n")
                    except Exception:
                        pass
                summary["rejected"] += len(batch)
                summary["sent"] += len(batch)
                break # move to next batch

            if status == 503 or status == 0: # 0 represents network error
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
                summary["accepted"] += len(accepted)

                if rejected:
                    # Rejected events from the server reply
                    # ASSUMPTION - confirm retry rule with Amir
                    resend_batch = []
                    rejected_reasons = {}
                    for r in rejected:
                        idx = r.get("index")
                        reason = r.get("reason")
                        if idx is not None and 0 <= idx < len(batch):
                            logger.info(f"Rejected index {idx}: {reason}")
                            resend_batch.append(batch[idx])
                            rejected_reasons[len(resend_batch) - 1] = reason

                    if resend_batch:
                        # resend ONLY those rejected events once
                        r_status, r_body = send_batch(url, key, resend_batch)
                        if r_status == 200:
                            r_acc, r_rej = parse_response(r_status, r_body)
                            summary["accepted"] += len(r_acc)
                            summary["rejected"] += len(r_rej)
                            for rr in r_rej:
                                r_idx = rr.get("index")
                                if r_idx is not None and 0 <= r_idx < len(resend_batch):
                                    ev = resend_batch[r_idx]
                                    rs = rr.get("reason", rejected_reasons.get(r_idx, "unknown"))
                                    with open(log_path, "a") as f:
                                        f.write(json.dumps({"event": ev, "reason": rs}) + "\n")
                        else:
                            # if resend fails, all considered rejected
                            summary["rejected"] += len(resend_batch)
                            for r_idx, ev in enumerate(resend_batch):
                                rs = rejected_reasons.get(r_idx, "unknown")
                                with open(log_path, "a") as f:
                                    f.write(json.dumps({"event": ev, "reason": rs}) + "\n")
                break # move to next batch

            # Any other status
            summary["failed"] += len(batch)
            summary["sent"] += len(batch)
            logger.error(f"Status {status}")
            break

        i += 1

    return summary

def main():
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
    invalid_count = mapped.get("invalid_count", 0)

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
