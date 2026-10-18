# Backend API (Role 5 — Tale)

FastAPI endpoint for investigating alerts: pattern-matches against
Neo4j, runs the investigation as an async Celery task, and exposes
one-click SOAR actions (isolate_host, revoke_tokens).

## Setup

1. `cp .env.example .env` (adjust values inside if needed — local defaults work as-is).
2. Start Neo4j: `docker run -d -p 7474:7474 -p 7687:7687 --name neo4j -e NEO4J_AUTH=neo4j/password docker.io/library/neo4j:latest`
3. Apply `neo4j_schema_setup.cypher` in the Neo4j Browser (http://localhost:7474, login neo4j/password) — paste its contents into the query bar and run.
4. Apply `seed_test_data.cypher` the same way — creates one test alert (`A-123`) so the test step below actually has data to find.
5. Start Redis: `docker run -d -p 6379:6379 --name redis docker.io/library/redis:latest`
6. `python3 -m venv venv && source venv/bin/activate`
   - If you hit an "externally-managed-environment" error on `pip install` without a venv active, this step is why it exists — always activate the venv first.
7. `pip install -r requirements.txt`
8. Run the API: `uvicorn investigate_endpoint:app --reload`
9. Run the worker (separate terminal, venv activated again): `celery -A celery_app worker --loglevel=info`

## Test

    curl -X POST http://localhost:8000/investigate \
      -H "Content-Type: application/json" \
      -d '{"alert_id": "A-123"}'

Returns a `task_id` instantly. Then:

    curl http://localhost:8000/investigate/PASTE_TASK_ID_HERE

Should return `"confidence": "CRITICAL"` with a detected kill chain.
