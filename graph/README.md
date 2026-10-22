# Graph Engine (Neo4j)

Owner: Amir (Graph Engineer). Everything the graph layer needs lives in this folder; nothing here edits another role's code.

## What is here
| Path | Purpose |
| ---- | ------- |
| `neo4j_schema_setup.cypher` | Constraints and indexes (run once per database) |
| `graph_loader.py` | Loads one ETL event into Neo4j (parameterized MERGE, idempotent) |
| `ingest_router.py` | FastAPI router `POST /ingest/events` (API key auth, 500 event cap) |
| `pattern_library.py` | 22 Cypher attack patterns (P-001..P-022) and `match_patterns(driver, alert_id)` |
| `pattern_evaluator.py` | Turns matched patterns into LOW / MEDIUM / HIGH / CRITICAL and kill-chain detection |
| `graph_queries.py` | `investigate_alert`, `get_alert_subgraph`, `correlate_host_alerts`, `to_cytoscape` |
| `fixtures/`, `scripts/`, `tests/` | Test alerts, local verification against a real Neo4j, unit tests |
| `docs/` | ETL contract, integration notes for each teammate |

## Using it from another folder
The modules import each other by plain name (`from pattern_library import ...`), the same way the orchestrator imports `ml-rag`. Add this folder to the path first:

    import sys
    sys.path.append("graph")   # path relative to the repo root
    from graph_queries import investigate_alert

For the FastAPI app: `from ingest_router import router, close_driver`, then `app.include_router(router)` and call `close_driver()` on shutdown.

## Environment variables
`NEO4J_URI`, `NEO4J_USER`, `NEO4J_PASSWORD`, `INGEST_API_KEY`. Optional: `NEO4J_DATABASE` (needed on Neo4j Aura). Never commit real values.

## Run the tests
    pip install -r requirements-dev.txt
    bash test_overall.sh

`bash scripts/verify_local.sh` loads the fixtures into a real Neo4j and asserts every pattern result. It needs the env vars above. It only deletes alerts whose id starts with `FX-`.

Timestamps everywhere are epoch milliseconds. Details: `docs/ETL_GRAPH_CONTRACT.md` and `docs/INTEGRATION_NOTES.md`.
