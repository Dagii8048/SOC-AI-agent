# ETL to Graph Contract

## Event Schema
- `alert` {id, level 0-15, name, timestamp, mitre[]}
- `host` {hostname, ip, os}
- `user` {username, domain, admin, failed_logins, last_failed}
- `process` {pid, start_time, name, path, args, hash, parent: {pid, start_time, name, path, args, hash}, children: [{pid, start_time, name, args}]}
- `network` [{src_ip, dest_ip, dest_port, protocol}]
- `files` [{path, hash, size, op: "read" | "write"}]
- `logged_in_hosts` []
- `scanned_hosts` []

## Graph Nodes and Relationships Created
- `Alert` -[:TRIGGERED_BY]-> `Process`
- `User` -[:OWNS]-> `Process`
- `Process` -[:RUNS_ON]-> `Host`
- Parent `Process` -[:SPAWNED]-> `Process`
- `Process` -[:SPAWNED]-> Child `Process`
- `Process` -[:CONNECTED_TO]-> `Network`
- `Process` -[:READS|WRITES]-> `File`
- `User` -[:LOGGED_IN]-> `Host` (from `logged_in_hosts`)
- `Host` -[:SCANNED]-> `Host` (from `scanned_hosts`)

## Known Limitations / Open Decisions
- Wazuh/osquery field mapping: verify against a real record.
- Missing start_time defaults to alert.timestamp.
- DETECTED_ON for process-less alerts left out of the graph as an open decision.
- User keyed by username merges Linux root across hosts.
- Severity mapping thresholds.
- Correlation window tuning (15m vs 30m).
- Alerts often fire on child process, so P-001 anchored on the parent may need a variant.
- P-005, P-013, P-017 are very loose. Need human input on if they should be tightened.
