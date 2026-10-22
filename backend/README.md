# Backend API (Role 5, Tale)

The front door of the SOC AI Agent. It takes requests from the dashboard,
hands investigations to a background worker, and runs one-click SOAR actions.

It does not contain graph, ML or agent code. It imports those from the
sibling folders `graph/` (Amir) and `orchestrator/` (Teferi, which in turn
uses `ml-rag/`).

## Files

| File | Job |
|---|---|
| `investigate_endpoint.py` | The API: `/investigate`, `/investigate/{id}`, `/actions/execute`, plus Amir's `/ingest/events` |
| `celery_app.py` | Worker setup (Redis is the queue) |
| `tasks.py` | The investigation: graph patterns, then the briefing from the agent |
| `actions.py` | The only two actions allowed to run: `isolate_host`, `revoke_tokens` |
| `repo_paths.py` | Lets this folder import `graph/` and `orchestrator/` |

## Settings (.env at the repo root, never commit it)

    NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD, NEO4J_DATABASE
    REDIS_HOST, REDIS_PORT
    INGEST_API_KEY      (needed by /ingest/events)
    SOAR_WEBHOOK_URL    (mock httpbin for now)

## Run (from the backend/ folder, venv active)

    pip install -r requirements.txt
    uvicorn investigate_endpoint:app --reload          # terminal 1
    celery -A celery_app worker --loglevel=info        # terminal 2

Redis must be running. The briefing also needs the packages in
`orchestrator/requirements.txt`, Qdrant and Ollama. Without them the
investigation still completes and `briefing` says why it is unavailable.

## Known follow-ups

- `/actions/execute` has no authentication yet. The dashboard must send a key too, so agree it with Wakjira first.
- `orchestrator/agent.py` still mocks its graph step and loads files by relative path; `tasks.py` works around the path issue until Teferi fixes it.
