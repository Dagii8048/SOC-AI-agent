# Graph Backend

## Start Neo4j
`docker run --name testneo4j -p7474:7474 -p7687:7687 -d -e NEO4J_AUTH=neo4j/password neo4j:5.19.0`

## Load Schema
Run `cypher-shell -u neo4j -p password -f neo4j_schema_setup.cypher`

## Load Fixtures
Run `python scripts/seed_fixtures.py`

## Tests
Run `pytest tests/`

## Example Curl
`curl -X POST -H "X-API-Key: your_key" -H "Content-Type: application/json" -d '{"events": []}' http://localhost:8000/ingest/events`
