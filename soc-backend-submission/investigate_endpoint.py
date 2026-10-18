"""
investigate_endpoint.py
Role 5 (Backend API) — Week 1-2 Deliverable
FastAPI endpoint that kicks off an investigation as a background
Celery task and returns a task_id immediately, instead of blocking
the request while the pattern matching (and eventually the LLM call)
runs.
"""

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from celery.result import AsyncResult

from celery_app import celery_app
from tasks import investigate_alert_task
from actions import execute_action

app = FastAPI()


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
