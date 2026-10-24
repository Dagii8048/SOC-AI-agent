// Talks to the FastAPI backend (backend/investigate_endpoint.py).
// Set VITE_API_BASE_URL in a frontend .env file to point somewhere else.

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || "http://localhost:8000";

async function errorFromResponse(response, fallback) {
  let detail = "";
  try {
    const body = await response.json();
    detail = typeof body.detail === "string" ? body.detail : "";
  } catch {
    // body was not JSON; use the fallback below
  }
  const error = new Error(detail || `${fallback} (HTTP ${response.status})`);
  error.status = response.status;
  return error;
}

// GET /alerts  ->  [{ id, name, severity, level, timestamp, hostname }]
export async function listAlerts(limit = 50) {
  const response = await fetch(`${API_BASE_URL}/alerts?limit=${limit}`);
  if (!response.ok) throw await errorFromResponse(response, "Could not load alerts");
  const data = await response.json();
  return data.alerts;
}

// GET /alerts/{id}/graph  ->  { nodes: [{data}], edges: [{data}] }  (Cytoscape format)
export async function getAlertGraph(alertId) {
  const response = await fetch(`${API_BASE_URL}/alerts/${encodeURIComponent(alertId)}/graph`);
  if (!response.ok) throw await errorFromResponse(response, "Could not load the attack graph");
  return await response.json();
}

// POST /investigate  ->  { task_id, status: "processing" }
export async function startInvestigation(alertId) {
  const response = await fetch(`${API_BASE_URL}/investigate`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ alert_id: alertId }),
  });
  if (!response.ok) throw await errorFromResponse(response, "Could not start the investigation");
  return await response.json();
}

// GET /investigate/{task_id}
//   200 { status: "processing" }            -> keep polling
//   200 { status: "complete", result: {} }  -> done
//   404                                     -> alert is not in the graph
//   500 { detail }                          -> the task failed, detail has the reason
export async function getInvestigation(taskId) {
  const response = await fetch(`${API_BASE_URL}/investigate/${encodeURIComponent(taskId)}`);
  if (!response.ok) throw await errorFromResponse(response, "Investigation failed");
  return await response.json();
}

// Start an investigation and wait until it finishes. Returns:
// { found, alert_id, confidence, matched_patterns, kill_chain_detected,
//   kill_chain_name, llm_invoked, briefing }
export async function investigateAlert(alertId, { intervalMs = 1500, timeoutMs = 180000 } = {}) {
  const { task_id } = await startInvestigation(alertId);
  const deadline = Date.now() + timeoutMs;

  while (Date.now() < deadline) {
    const data = await getInvestigation(task_id);
    if (data.status === "complete") return data.result;
    await new Promise((resolve) => setTimeout(resolve, intervalMs));
  }
  throw new Error("Investigation timed out. Is the Celery worker running?");
}

// POST /actions/execute  (isolate_host needs {hostname}, revoke_tokens needs {username})
export async function executeAction(action, params) {
  const response = await fetch(`${API_BASE_URL}/actions/execute`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ action, params }),
  });
  if (!response.ok) throw await errorFromResponse(response, "Action failed");
  return await response.json();
}
