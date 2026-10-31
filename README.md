<img width="1280" height="720" alt="RAG based SOC AI agent-Cover" src="https://github.com/user-attachments/assets/52cb5bdb-079e-45a6-ba93-abea9ef79e23" />

# Graph-Based RAG SOC AI Agent 🛡️

An intelligent, locally hosted SOC assistant that ingests security alerts, reconstructs attack chains using Neo4j, and leverages Retrieval-Augmented Generation (RAG) with a local LLM to generate actionable security analyst briefings.

## 🚀 Key Features

- **100% Local:** Runs entirely on your machine using Ollama (Llama 3.1) and Docker.
- **Graph-Based Detection:** Maps security alerts to 22 MITRE ATT&CK Cypher patterns to identify hidden attack chains.
- **Smart Triage:** Uses XGBoost to classify potential false positives and Qdrant RAG to retrieve similar historical incidents.
- **Human-in-the-Loop:** AI recommends response actions (e.g., "Isolate Host"), but requires human approval before execution.

## 🏗️ Architecture Flow

```text
Wazuh / Osquery
       │
       ▼
ETL Pipeline (Python)
       │
       ▼
Neo4j Graph Database
       │
       ▼
Pattern Matching + Qdrant RAG
       │
       ▼
LangGraph Orchestrator
       │
       ▼
Llama 3.1 (Local LLM)
       │
       ▼
FastAPI Backend
       │
       ▼
React Dashboard (Cytoscape.js)
```

## 📂 Repository Structure

```text
soc-ai-agent/
│
├── etl-pipeline/
│   └── Normalizes Wazuh/Osquery logs to UTC
│       and maps them to the graph schema.
│
├── graph/
│   └── Neo4j schema, graph loader,
│       and 22 Cypher attack patterns.
│
├── ml-rag/
│   └── XGBoost false-positive classifier
│       and Qdrant vector search.
│
├── orchestrator/
│   └── LangGraph workflow connecting
│       ML, RAG, and the local LLM.
│
├── backend/
│   └── FastAPI endpoints for investigation
│       and Celery background tasks.
│
└── src/
    └── React/Cytoscape.js dashboard
        for security analysts.
```

## 🚀 Quick Start

### Prerequisites

Make sure you have the following installed:

- Docker Desktop
- Python 3.12
- Node.js
- [Ollama](https://ollama.com/)

Pull the required LLM:

```bash
ollama pull llama3.1:8b
```

### 1. Start the Databases

Open Docker Desktop and ensure Neo4j and Qdrant are running.

Start Redis for Celery:

```bash
docker run -d -p 6379:6379 --name redis redis
```

### 2. Load Test Data

**Load Graph Fixtures (from the root directory):**

```bash
cd backend
python ../graph/scripts/seed_fixtures.py
```

**Load RAG Data (in a new terminal):**

```bash
cd ml-rag
python rag_pipeline.py
```

### 3. Start the Backend (Terminal 1)

```bash
cd backend
python -m uvicorn investigate_endpoint:app --reload
```

### 4. Start the Celery Worker (Terminal 2)

```bash
cd backend
celery -A celery_app worker --loglevel=info --pool=solo
```

### 5. Start the Frontend (Terminal 3)

Run these commands from the project root directory:

```bash
npm install
npm run dev
```

Once all services are running, open the dashboard:

**http://localhost:5173**

## 👥 Team

| Team Member | Responsibility | Technologies |
|---|---|---|
| **Amir** | Graph Engine | Neo4j, Cypher |
| **Beka** | ETL Pipeline | Data Mapping, UTC Normalization |
| **Dagi** | ML/RAG & Orchestrator | XGBoost, Qdrant, LangGraph |
| **Talegeta** | Backend API | FastAPI, Celery |
| **Wakjira** | Frontend Dashboard | React, Cytoscape.js |

## ⚠️ MVP Limitations

- **Limited Training Dataset:** The ML classifier is trained on only 50 synthetic incidents. Production deployment would require a significantly larger and more representative dataset (5,000+ incidents).
- **CPU-Based LLM Inference:** The local LLM runs on CPU, resulting in slower inference times, although it eliminates cloud inference costs.
- **No API Authentication:** API endpoints are currently unauthenticated and intended for localhost use only. Production deployment requires proper authentication and authorization mechanisms.

---

**Built with a focus on local AI, graph-based threat detection, and intelligent SOC automation. 🛡️**
