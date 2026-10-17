# ETL to Graph Contract

## Event Schema (Pydantic style)
- `alert` {id, level 0-15, name, timestamp}
- `host` {hostname, ip, os}
- `user` {username, domain, admin}
- `process` {pid, start_time, name, path, args, parent: {pid, start_time, name}}
- `network` [{dest_ip, dest_port, protocol}]
- `files` [{path, op: "read" | "write"}]

## Graph Nodes and Relationships Created
- `Alert` -[:TRIGGERED_BY]-> `Process`
- `Alert` -[:DETECTED_ON]-> `Host` | `User`
- `User` -[:OWNS]-> `Process`
- `Process` -[:RUNS_ON]-> `Host`
- Parent `Process` -[:SPAWNED]-> `Process`
- `Process` -[:CONNECTED_TO]-> `Network`
- `Process` -[:READS|WRITES]-> `File`
- `User` -[:LOGGED_IN]-> `Host`
- `Host` -[:SCANNED]-> `Host`

## Known Limitations / Mapping Notes
- Verify against a real record: Wazuh/Osquery fields mapping.
- Missing start_time defaults to alert.timestamp.
