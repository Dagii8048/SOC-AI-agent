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
- Validations happen per event individually, so you will receive partial accepted/rejected counts.
- `app.include_router(ingest_router.router)` must be added to your FastAPI startup to mount the ingestion routes.
- `neo4j_driver` is managed via environment variables. Make sure to call `ingest_router.close_driver()` on application shutdown.
- Ensure CORS is configured for `http://localhost:5173`.
- `tasks.py` currently returns `{"error": ...}` inside a 200 OK success envelope for missing investigations. Please use `investigate_alert`'s explicit `{"found": False}` flag instead.
- Note that `/actions/execute` has no auth and posts to httpbin.org.

## Wakjira
- Use the `get_alert_subgraph` shape and map node types to your labels. Nodes now carry the appropriate domain ID instead of internal Neo4j node IDs.

## Teferi
- When integrating with the graph for RAG, the input shape should be constructed safely.
- Please sanitize and truncate log strings appropriately before injecting them into the LLM prompt to prevent prompt injection attacks or overwhelming token limits.

## Database Name
Tale: You can set `NEO4J_DATABASE` in your environment (e.g. `NEO4J_DATABASE=neo4j`) when connecting to Neo4j Aura clusters that fail to resolve the default home database.

## Graph Formats
Wakjira: `graph_queries.to_cytoscape(subgraph)` handles formatting for Cytoscape.js.
- **Original Subgraph**: `{"nodes": [...], "edges": [{"from", "to", "type"}]}`
- **Cytoscape**: `{"nodes": [{"data": {"id", "label", "type", ...props}}], "edges": [{"data": {"id", "source", "target", "type"}}]}`

## Integration risks
- Teferi and Dagi: our "confidence" is LOW/MEDIUM/HIGH/CRITICAL (a word). Dagi's classifier "confidence" is a number from 0 to 1. Use different names in the orchestrator.
- The ML classifier maps unseen alert types to the last known type. auto_close must be disabled when the alert type is not in the encoder's classes.
- Correlation window: our default is 30 minutes (1800000 ms), Beka's ETL clusters over 15 minutes. The team must pick one.
- Tale: his submitted tasks.py returns {"error"} inside a 200 and does not call the classifier or RAG.
