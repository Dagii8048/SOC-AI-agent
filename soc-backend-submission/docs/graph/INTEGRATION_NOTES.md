# Integration Notes

## Beka
- Please update `quick_etl.py` to:
  - Multiply the generated `epoch` by 1000 so it returns milliseconds instead of seconds.
  - Pass the original Wazuh/osquery alert id to `alert.id` in the JSON structure.
  - Please extract and send structured fields (e.g. `pid`, `parent pid`, `user`, `dest_ip`, `dest_port`, `file_path`) in their respective schemas rather than stuffing them into a single free-text string in the `evidence` field.

## Tale
- Note that `get_alert_subgraph` and `investigate_alert` are in `graph_queries.py`.
- Auth is now handled as a FastAPI dependency in the router, returning 503 or 401 before body parsing.
- A content-length cap of 10MB has been added before parsing the JSON.
- `neo4j_driver` is now expected to be managed via environment variables and lazy initialization via `get_driver()` instead of `app.state`. A `close_driver()` hook is available for shutdown.
- Validations happen per event individually, so you will receive partial accepted/rejected counts.

## Wakjira
- Use the `get_alert_subgraph` shape and map node types to your labels. Nodes now carry the appropriate domain ID instead of internal Neo4j node IDs.
