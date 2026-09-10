
# SOC AI Agent (Graph-Based RAG)

**Goal:** AI-powered SOC analyst assistant that reduces investigation time from 15 minutes to <10 seconds.

## Architecture

See `docs/architecture.md` for the full data flow.

## Team Roles

| Engineer | Role                             |
| -------- | -------------------------------- |
| Teferi   | Orchestrator (LangGraph)         |
| Amir     | Graph Engineer (Neo4j/Cypher)    |
| Beka     | ETL Engineer (Wazuh/Osquery)     |
| Dagi     | ML/RAG Engineer (XGBoost/Qdrant) |
| Tale     | Backend API (FastAPI)            |
| Wakjira  | Frontend (React/Cytoscape)       |
