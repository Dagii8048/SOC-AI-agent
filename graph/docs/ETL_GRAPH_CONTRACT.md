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

**Important Data Constraints:**
- All timestamps MUST be epoch milliseconds.
- String fields are length-capped internally during ingestion: `id` (256), `name` (256), `path` (1024), `args` (4096), `hash` (256), `hostname` (256), `username` (256), `ip` (256).

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

## Pattern Required Fields Mapping
| Pattern | Required Nodes and Relationships | Event Field | Stays Dark if Missing |
| ------- | -------------------------------- | ----------- | --------------------- |
| P-001 | `User-[:OWNS]->Process-[:SPAWNED]->Process` | `user`, `process`, `process.children` (or parent) | Yes |
| P-002 | `User-[:LOGGED_IN]->Host` (multiple hosts) | `user`, `logged_in_hosts` | Yes |
| P-003 | `Process-[:READS]->File` | `process`, `files` (with op read) | Yes |
| P-004 | `Process-[:CONNECTED_TO]->Network` | `process`, `network` | Yes |
| P-005 | `User-[:OWNS]->Process-[:SPAWNED]->Process` | `user.admin`, `process`, `process.children` | Yes |
| P-006 | `Process-[:WRITES]->File` | `process`, `files` (with op write) | Yes |
| P-007 | `Process-[:READS]->File`, `Process-[:CONNECTED_TO]->Network` | `process`, `files`, `network` | Yes |
| P-008 | `Process-[:WRITES]->File` | `process`, `files` (with op write) | Yes |
| P-009 | `Host-[:SCANNED]->Host` | `scanned_hosts` | Yes |
| P-010 | `User-[:OWNS]->Process` | `user`, `process` | Yes |
| P-011 | `Process` | `process` | Yes |
| P-012 | `Process-[:SPAWNED]->Process` | `process`, `process.children` (or parent) | Yes |
| P-013 | `Process-[:WRITES]->File` | `process`, `files` (with op write) | Yes |
| P-014 | `Process-[:WRITES]->File` | `process`, `files` (with op write) | Yes |
| P-015 | `Process-[:SPAWNED]->Process` | `process`, `process.children` (or parent) | Yes |
| P-016 | `Process` | `process` | Yes |
| P-017 | `Process-[:CONNECTED_TO]->Network` | `process`, `network` | Yes |
| P-018 | `User-[:OWNS]->Process` | `user.failed_logins`, `user.last_failed`, `process` | Yes |
| P-019 | `Process-[:READS]->File` | `process`, `files` (with op read) | Yes |
| P-020 | `Process-[:CONNECTED_TO]->Network` | `process`, `network` | Yes |
| P-021 | `Process` | `process` | Yes |
| P-022 | `Process-[:WRITES]->File` (optional File) | `process` (and optional `files` write) | Yes |
