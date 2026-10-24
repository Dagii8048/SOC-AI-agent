# Backend API

The front door of the SOC AI Agent. It takes requests from the dashboard and from the ETL, hands investigations to a background worker, and runs one-click actions.

It contains no graph, ML or agent logic of its own. It imports `graph/` (patterns and the graph database code) and `orchestrator/` (the briefing agent) through `repo_paths.py`.

## How a request flows

1. `POST /investigate` puts a ticket in Redis and returns a `task_id` straight away.
2. The Celery worker picks the ticket up, runs the graph patterns (`graph/graph_queries.py`), and for MEDIUM or higher confidence asks the agent for a briefing.
3. `GET /investigate/{task_id}` returns `processing` until the worker is done, then `complete` with the result.

So three things must be running: **Redis, the API, and the worker.** If the worker is missing, requests stay on `processing` forever.

## Files

| File | Job |
|---|---|
| `investigate_endpoint.py` | The API (FastAPI). Also mounts the `/ingest/events` routes from `graph/` |
| `celery_app.py` | Worker setup (Redis is the queue and result store) |
| `tasks.py` | The investigation task |
| `actions.py` | The only actions allowed to run: `isolate_host`, `revoke_tokens` |
| `repo_paths.py` | Lets this folder import `graph/` and `orchestrator/` |

## Setup

1. **Clone the repo** and create a private Python environment outside it:

       python3 -m venv ~/soc-venv
       source ~/soc-venv/bin/activate
       pip install -r backend/requirements.txt

2. **Start Redis** (Docker or Podman):

       docker run -d -p 6379:6379 --name redis docker.io/library/redis:alpine

   If it says the name `redis` is already in use, run `docker start redis` instead. Check with `redis-cli ping` (expect `PONG`).

3. **Create your `.env`** in the repo root. Never commit it; Git ignores it.

       cp .env.example .env

   Fill in the Neo4j values Amir sends privately and the shared ingest key:

       NEO4J_URI=neo4j+s://<id>.databases.neo4j.io
       NEO4J_USER=<instance id>
       NEO4J_PASSWORD=<password>
       NEO4J_DATABASE=<database name>
       INGEST_API_KEY=<shared key>

   **The name is `NEO4J_USER`, not `NEO4J_USERNAME`.** The code ignores `NEO4J_USERNAME` and logs in as `neo4j`, which fails on Aura. If you see "routing information" errors, change `neo4j+s://` to `bolt+s://`.

## Run

Use one terminal per service. Each new terminal needs the environment and your settings again.

    # Terminal 1: the API
    cd backend
    source ~/soc-venv/bin/activate
    set -a; source ../.env; set +a
    uvicorn investigate_endpoint:app --reload --port 8000

    # Terminal 2: the worker
    cd backend
    source ~/soc-venv/bin/activate
    set -a; source ../.env; set +a
    celery -A celery_app worker --loglevel=info

On Windows, start the worker with `--pool=solo` added, and set the environment variables with your shell's own syntax.

API docs are at http://127.0.0.1:8000/docs.

## Try it

Load the test alerts into the graph once (from the repo root, with `.env` loaded):

    bash graph/scripts/verify_local.sh

Then investigate the kill-chain alert:

    curl -s -X POST http://127.0.0.1:8000/investigate -H "Content-Type: application/json" -d '{"alert_id":"FX-WIN-100"}'
    # wait a few seconds, then use the task_id you got:
    curl -s http://127.0.0.1:8000/investigate/<task_id> | python3 -m json.tool

Expected for `FX-WIN-100`: `status: complete`, `confidence: CRITICAL`, 5 matched patterns, and the kill chain "Phishing -> Credential Dumping -> Exfiltration".

## Endpoints

| Method and path | What it does |
|---|---|
| `POST /investigate` | Body `{"alert_id": "..."}`. Returns `task_id` |
| `GET /investigate/{task_id}` | `processing`, then `complete` with the result. 404 if the alert is not in the graph. 500 with the error type and message if the task failed |
| `POST /ingest/events` | The ETL sends mapped events here. Header `x-api-key` must match `INGEST_API_KEY` (wrong or missing: 401) |
| `POST /actions/execute` | Body `{"action": "isolate_host", "params": {...}}`. Only whitelisted actions run |
| `GET /alerts` | The dashboard's alert list: `{"alerts": [{id, name, severity, level, timestamp, hostname}]}`, newest first. Optional `?limit=` (1 to 200, default 50) |
| `GET /alerts/{alert_id}/graph` | That alert's attack graph in Cytoscape format: `{"nodes": [{"data": ...}], "edges": [{"data": ...}]}`. 404 if the alert is not in the graph |

CORS allows the dashboard at `http://localhost:5173`.

## The dashboard

The React dashboard lives at the repo root (`src/`). It lists the alerts from `GET /alerts`, draws the selected alert's graph from `GET /alerts/{id}/graph`, and runs `POST /investigate` + polling when you press "Investigate with AI". With the API, the worker and Redis running (see above):

    npm install
    npm run dev

Open exactly http://localhost:5173 (the API only allows that address). To use another API address, create a frontend `.env` with `VITE_API_BASE_URL=http://host:port`.

## The briefing

The `briefing` field comes from the LangGraph agent in `orchestrator/`. It needs extra pieces, and without them the investigation still completes and `briefing` says why (for example `No module named 'numpy'`):

- `pip install -r orchestrator/requirements.txt` (large download)
- Qdrant running (for similar past incidents)
- Ollama running with the model in `OLLAMA_MODEL` (`ollama pull llama3.2:3b`), plus optional `OLLAMA_HOST` and `OLLAMA_TIMEOUT_SECONDS` in `.env`

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| Stays on `processing` | The worker is not running, or Redis is down |
| `500` with an authentication error | Wrong `NEO4J_USER` or password, or the Aura instance is paused |
| `404 Alert ... not found` | The alert is not in the graph; load the fixtures or ingest it first |
| Lots of "property/relationship does not exist" warnings in the worker | Harmless. Some patterns look for data the test alerts do not have |
| `503 INGEST_API_KEY not configured` | The API terminal did not load `.env` |

## Known limits

- `/investigate`, `/alerts`, `/alerts/{id}/graph` and `/actions/execute` have no authentication yet. Anyone who can reach the API can call them.
- Actions go to `SOAR_WEBHOOK_URL`, which is a test site (httpbin) by default, so nothing is really isolated.
