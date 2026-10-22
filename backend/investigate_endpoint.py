"""
investigate_endpoint.py
Role 5 (Backend API): the front door of the whole system.

What changed from the first version:
  - Mounts Amir's /ingest/events routes so Beka's ETL can send alerts in.
  - CORS: lets the dashboard (running at http://localhost:5173) call this API.
    Without it the browser blocks the dashboard's requests.
  - Closes the shared Neo4j connection when the API shuts down.
  - A finished investigation with found=False now returns a real 404.
"""
import repo_paths  # noqa: F401  (must stay first: makes graph/ importable)

from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from celery.result import AsyncResult

import ingest_router  # Amir's ingestion routes, in graph/
from celery_app import celery_app
from tasks import investigate_alert_task
from actions import execute_action


@asynccontextmanager
async def lifespan(app: FastAPI):
    yield  # the API runs while we are paused here
    ingest_router.close_driver()  # runs once, on shutdown


app = FastAPI(lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(ingest_router.router)


class InvestigateRequest(BaseModel):
    alert_id: str


@app.post("/investigate")
def investigate(req: InvestigateRequest):
    task = investigate_alert_task.delay(req.alert_id)
    return {"task_id": task.id, "status": "processing"}


@app.get("/investigate/{task_id}")
def get_investigation_result(task_id: str):
    result = AsyncResult(task_id, app=celery_app)

    if result.state == "PENDING":
        return {"task_id": task_id, "status": "processing"}
    elif result.state == "FAILURE":
        raise HTTPException(status_code=500, detail=str(result.result))
    elif result.state == "SUCCESS":
        if result.result.get("found") is False:
            raise HTTPException(status_code=404, detail=f"Alert {result.result['alert_id']} not found")
        return {"task_id": task_id, "status": "complete", "result": result.result}
    else:
        return {"task_id": task_id, "status": result.state}


class ActionRequest(BaseModel):
    action: str
    params: dict


@app.post("/actions/execute")
def execute_one_click_action(req: ActionRequest):
    try:
        return execute_action(req.action, req.params)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
