# Graph-Based RAG SOC AI Agent 🛡️

An intelligent, locally-hosted SOC assistant that ingests security alerts, reconstructs attack chains using Neo4j, and uses RAG + a local LLM to generate actionable analyst briefings.

## 🚀 Key Features
- **100% Local:** Runs entirely on your machine via Ollama (Llama 3.1) and Docker.
- **Graph Detection:** Maps alerts to 22 MITRE ATT&CK Cypher patterns to find hidden kill chains.
- **Smart Triage:** Uses XGBoost to auto-close false positives and Qdrant RAG to find similar past incidents.
- **Human-in-the-Loop:** AI suggests actions (e.g., "Isolate Host"), but requires human approval.

## 🏗️ Architecture Flow
`Wazuh/Osquery` ➔ `ETL (Python)` ➔ `Neo4j Graph` ➔ `Pattern Match` + `Qdrant RAG` ➔ `LangGraph` ➔ `Llama 3.1` ➔ `FastAPI` ➔ `React UI`

## 📂 Repo Structure
- `etl/` - Normalizes Wazuh/Osquery logs to UTC and maps them to the graph schema.
- `graph/` - Neo4j schema, graph loader, and 22 Cypher attack patterns.
- `ml-rag/` - XGBoost false-positive classifier and Qdrant vector search.
- `orchestrator/` - LangGraph workflow connecting ML, RAG, and the LLM.
- `backend/` - FastAPI endpoints for investigation and actions.
- `frontend/` - React/Cytoscape.js dashboard for analysts.

## 🚀 Quick Start
**Prerequisites:** Docker Desktop, Python 3.12, Node.js, and [Ollama](https://ollama.com/) (`ollama pull llama3.1:8b`).

1. **Start DBs:** `docker compose up -d`
2. **Load Graph:** `cd etl && python quick_etl.py`
3. **Load RAG:** `cd ml-rag && python rag_pipeline.py`
4. **Run Agent (CLI):** `cd orchestrator && python agent.py`
5. **Run App:** Start `uvicorn main:app` (backend) and `npm run dev` (frontend).

## 👥 Team
- **Amir:** Graph Engine (Neo4j, Cypher)
- **Beka:** ETL Pipeline (Data Mapping, UTC Normalization)
- **Dagi:** Orchestrator & ML/RAG (LangGraph, XGBoost, Qdrant)
- **Talegeta:** Backend API (FastAPI)
- **Wakjira:** Frontend Dashboard (React, Cytoscape)

## ⚠️ MVP Limitations
- ML classifier trained on 50 synthetic incidents (production needs 5k+).
- LLM runs on CPU locally (slower inference, but zero cloud cost).
