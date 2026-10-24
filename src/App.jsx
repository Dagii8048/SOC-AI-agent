import { useCallback, useEffect, useState } from "react";
import AttackGraph from "./AttackGraph";
import { listAlerts, getAlertGraph, investigateAlert, executeAction } from "./api";
import "./App.css";
import "./Live.css";

const HIGH_SEVERITIES = ["High", "Critical"];
const REFRESH_MS = 30000;

function severityClass(severity) {
  return `sev-${String(severity || "low").toLowerCase()}`;
}

function formatTime(ms) {
  if (!ms) return "unknown";
  return new Date(ms).toLocaleString();
}

function BriefingView({ result }) {
  if (!result.llm_invoked) {
    return <p className="empty-note">Low risk: the AI briefing was not needed.</p>;
  }
  const briefing = result.briefing;
  if (!briefing) {
    return <p className="empty-note">No briefing was returned.</p>;
  }
  if (briefing.error) {
    return <p className="error-text">AI briefing unavailable: {briefing.error}</p>;
  }
  if (briefing.summary) {
    return <p>{briefing.summary}</p>;
  }
  return (
    <>
      <p>{briefing.executive_summary}</p>
      {briefing.threat_level && (
        <p className="briefing-meta">
          <strong>AI threat level:</strong> {briefing.threat_level}
        </p>
      )}
      {Array.isArray(briefing.mitre_techniques) && briefing.mitre_techniques.length > 0 && (
        <p className="briefing-meta">
          <strong>MITRE:</strong> {briefing.mitre_techniques.join(", ")}
        </p>
      )}
      {Array.isArray(briefing.recommendations) && briefing.recommendations.length > 0 && (
        <ul className="briefing-list">
          {briefing.recommendations.map((item, index) => (
            <li key={index}>{item}</li>
          ))}
        </ul>
      )}
    </>
  );
}

function App() {
  const [alerts, setAlerts] = useState([]);
  const [alertsError, setAlertsError] = useState(null);
  const [alertsLoading, setAlertsLoading] = useState(true);

  const [selectedId, setSelectedId] = useState(null);
  const [graph, setGraph] = useState(null);
  const [graphLoading, setGraphLoading] = useState(false);
  const [graphError, setGraphError] = useState(null);

  // runs[alertId] = { status: "running" | "done" | "error", result, error }
  const [runs, setRuns] = useState({});
  // decisions[alertId] = "approved" | "rejected" | "escalated"
  const [decisions, setDecisions] = useState({});
  const [action, setAction] = useState({ status: "idle", message: "" });

  // ---- load the alert list (and refresh it every 30 seconds) ----
  const loadAlerts = useCallback(async () => {
    try {
      const data = await listAlerts();
      setAlerts(data);
      setAlertsError(null);
      setSelectedId((current) => current || (data.length > 0 ? data[0].id : null));
    } catch (err) {
      setAlertsError(
        err.status
          ? `The backend answered with an error: ${err.message}`
          : "Cannot reach the backend. Is the API running on port 8000?"
      );
    } finally {
      setAlertsLoading(false);
    }
  }, []);

  useEffect(() => {
    loadAlerts();
    const timer = setInterval(loadAlerts, REFRESH_MS);
    return () => clearInterval(timer);
  }, [loadAlerts]);

  // ---- load the attack graph of the selected alert ----
  useEffect(() => {
    if (!selectedId) {
      setGraph(null);
      return undefined;
    }
    let cancelled = false;
    setGraph(null);
    setGraphError(null);
    setGraphLoading(true);
    setAction({ status: "idle", message: "" });

    getAlertGraph(selectedId)
      .then((data) => {
        if (!cancelled) setGraph(data);
      })
      .catch((err) => {
        if (!cancelled) setGraphError(err.message);
      })
      .finally(() => {
        if (!cancelled) setGraphLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, [selectedId]);

  const selected = alerts.find((a) => a.id === selectedId) || null;
  const run = selectedId ? runs[selectedId] : null;
  const result = run && run.status === "done" ? run.result : null;
  const decision = selectedId ? decisions[selectedId] : null;

  // ---- run the investigation (patterns + AI briefing) ----
  const handleInvestigate = async () => {
    if (!selectedId) return;
    const id = selectedId;
    setRuns((r) => ({ ...r, [id]: { status: "running" } }));
    try {
      const data = await investigateAlert(id);
      setRuns((r) => ({ ...r, [id]: { status: "done", result: data } }));
    } catch (err) {
      setRuns((r) => ({ ...r, [id]: { status: "error", error: err.message } }));
    }
  };

  const decide = (value) => setDecisions((d) => ({ ...d, [selectedId]: value }));

  const handleIsolate = async () => {
    if (!selected || !selected.hostname) return;
    if (!window.confirm(`Isolate host ${selected.hostname}? This sends the containment action to the SOAR webhook.`)) {
      return;
    }
    setAction({ status: "running", message: "Sending..." });
    try {
      const data = await executeAction("isolate_host", { hostname: selected.hostname });
      setAction({ status: "done", message: `Isolation of ${data.params.hostname} was ${data.status}.` });
    } catch (err) {
      setAction({ status: "error", message: err.message });
    }
  };

  // ---- numbers for the summary cards ----
  const highRisk = alerts.filter((a) => HIGH_SEVERITIES.includes(a.severity)).length;
  const investigated = Object.entries(runs).filter(([, r]) => r.status === "done");
  const pendingReview = investigated.filter(([id]) => !decisions[id]).length;

  return (
    <div className="app">
      <header className="dashboard-header">
        <div>
          <p className="system-label">SECURITY OPERATIONS CENTER</p>
          <h1>SOC Investigation Dashboard</h1>
          <p className="dashboard-description">
            Security alert investigation, attack visualization and analyst decision support
          </p>
        </div>

        {alertsError ? (
          <div className="status-badge offline">
            <span className="status-dot"></span>
            BACKEND OFFLINE
          </div>
        ) : (
          <div className="status-badge">
            <span className="status-dot"></span>
            SYSTEM ONLINE
          </div>
        )}
      </header>

      <section className="summary-grid">
        <div className="summary-card">
          <span className="summary-label">ACTIVE ALERTS</span>
          <strong>{alerts.length}</strong>
          <span className="summary-info">In the attack graph</span>
        </div>

        <div className="summary-card">
          <span className="summary-label">HIGH RISK</span>
          <strong>{highRisk}</strong>
          <span className="summary-info">High or critical severity</span>
        </div>

        <div className="summary-card">
          <span className="summary-label">AI ANALYSIS</span>
          <strong>{investigated.length}</strong>
          <span className="summary-info">Investigated this session</span>
        </div>

        <div className="summary-card">
          <span className="summary-label">PENDING REVIEW</span>
          <strong>{pendingReview}</strong>
          <span className="summary-info">Awaiting analyst decision</span>
        </div>
      </section>

      <section className="panel alerts-panel">
        <div className="panel-header">
          <div>
            <span className="panel-label">INCOMING ALERTS</span>
            <h2>Alerts</h2>
          </div>
          <button className="refresh-button" onClick={loadAlerts}>
            Refresh
          </button>
        </div>

        {alertsError && <p className="error-text panel-pad">{alertsError}</p>}
        {!alertsError && alertsLoading && <p className="empty-note panel-pad">Loading alerts...</p>}
        {!alertsError && !alertsLoading && alerts.length === 0 && (
          <p className="empty-note panel-pad">
            No alerts in the graph yet. Send events to POST /ingest/events or load the test data
            (graph/scripts/seed_fixtures.py).
          </p>
        )}

        <div className="alert-list">
          {alerts.map((a) => (
            <button
              key={a.id}
              className={`alert-row${a.id === selectedId ? " active" : ""}`}
              onClick={() => setSelectedId(a.id)}
            >
              <span className={`sev-pill ${severityClass(a.severity)}`}>{a.severity}</span>
              <span className="alert-name">{a.name}</span>
              <span className="alert-meta">
                {a.hostname || "no host"} · {a.id}
              </span>
              {decisions[a.id] && <span className="alert-decision">{decisions[a.id]}</span>}
            </button>
          ))}
        </div>
      </section>

      <main className="dashboard-grid">
        <section className="panel attack-panel">
          <div className="panel-header">
            <div>
              <span className="panel-label">NETWORK INVESTIGATION</span>
              <h2>Attack Graph</h2>
            </div>

            <span className="live-badge">LIVE</span>
          </div>

          <AttackGraph graph={graph} loading={graphLoading} error={graphError} />
        </section>

        <section className="panel alert-panel">
          <div className="panel-header">
            <div>
              <span className="panel-label">SECURITY EVENT</span>
              <h2>Active Incident</h2>
            </div>

            {selected && (
              <span className={`severity-badge ${severityClass(selected.severity)}`}>
                {selected.severity}
              </span>
            )}
          </div>

          {selected ? (
            <div className="incident-content">
              <div className="incident-row">
                <span>Alert ID</span>
                <strong>{selected.id}</strong>
              </div>
              <div className="incident-row">
                <span>Detection</span>
                <strong>{selected.name}</strong>
              </div>
              <div className="incident-row">
                <span>Host</span>
                <strong>{selected.hostname || "unknown"}</strong>
              </div>
              <div className="incident-row">
                <span>Detected</span>
                <strong>{formatTime(selected.timestamp)}</strong>
              </div>
              <div className="incident-row">
                <span>Status</span>
                <strong className="investigating">
                  {run && run.status === "running"
                    ? "Investigating..."
                    : result
                      ? "Investigated"
                      : "Not investigated"}
                </strong>
              </div>

              <button
                className="investigate-button"
                onClick={handleInvestigate}
                disabled={!selected || (run && run.status === "running")}
              >
                {run && run.status === "running" ? "Investigating..." : "Investigate with AI"}
              </button>

              {run && run.status === "error" && (
                <div className="investigation-error">{run.error}</div>
              )}
            </div>
          ) : (
            <p className="empty-note panel-pad">Select an alert from the list.</p>
          )}
        </section>

        <section className="panel ai-panel">
          <div className="panel-header">
            <div>
              <span className="panel-label">AI SECURITY ANALYSIS</span>
              <h2>Investigation Results</h2>
            </div>

            <span className="ai-badge">AI</span>
          </div>

          {result ? (
            <div className="ai-result">
              <div className="risk-section">
                <span>Risk Assessment</span>
                <div className={`risk-value ${severityClass(result.briefing?.threat_level || result.confidence)}`}>
                  {result.briefing?.threat_level || result.confidence}
                </div>
              </div>

              {result.kill_chain_detected && (
                <div className="finding">
                  <h3>Kill Chain Detected</h3>
                  <p>{result.kill_chain_name}</p>
                </div>
              )}

              <div className="finding">
                <h3>AI Briefing</h3>
                <BriefingView result={result} />
              </div>
            </div>
          ) : (
            <p className="empty-note panel-pad">
              {run && run.status === "running"
                ? "Investigating... the AI briefing can take a minute."
                : "Run \"Investigate with AI\" to see the result."}
            </p>
          )}
        </section>

        <section className="panel evidence-panel">
          <div className="panel-header">
            <div>
              <span className="panel-label">INVESTIGATION DATA</span>
              <h2>Evidence & Findings</h2>
            </div>
          </div>

          {result ? (
            <div className="evidence-list">
              {result.matched_patterns.length === 0 && (
                <p className="empty-note panel-pad">No attack patterns matched this alert.</p>
              )}
              {result.matched_patterns.map((pattern, index) => (
                <div className="evidence-item" key={pattern.id}>
                  <span className="evidence-icon">{String(index + 1).padStart(2, "0")}</span>
                  <div>
                    <strong>
                      {pattern.id} · {pattern.name}
                    </strong>
                    <p>MITRE {pattern.mitre}</p>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <p className="empty-note panel-pad">Matched attack patterns appear here.</p>
          )}
        </section>
      </main>

      <section className="panel approval-panel">
        <div className="panel-header">
          <div>
            <span className="panel-label">ANALYST DECISION</span>
            <h2>Investigation Approval</h2>
          </div>

          <span className="review-badge">HUMAN REVIEW REQUIRED</span>
        </div>

        <p className="approval-description">
          Review the AI investigation results and evidence before selecting the appropriate
          analyst decision.
        </p>

        <div className="approval-actions">
          <button 
            className="action-button approve" 
            disabled={!result || decision === "approved"} 
            onClick={() => decide("approved")}
          >
            Approve Investigation
          </button>

          <button 
            className="action-button reject" 
            disabled={!result || decision === "rejected"} 
            onClick={() => decide("rejected")}
          >
            Reject Finding
          </button>

          <button 
            className="action-button escalate" 
            disabled={!result || decision === "escalated"} 
            onClick={() => decide("escalated")}
          >
            Escalate Incident
          </button>

          <button
            className="action-button isolate"
disabled={!result || !selected || !selected.hostname || action.status === "running" || action.status === "done"}
            onClick={handleIsolate}
          >
            Isolate Host (SOAR)
          </button>
        </div>

        {decision && (
          <p className={`decision-note decision-${decision}`}>Analyst decision: {decision.toUpperCase()}</p>
        )}
        {action.status !== "idle" && (
          <p className={action.status === "error" ? "error-text panel-pad" : "decision-note"}>
            {action.message}
          </p>
        )}
      </section>
    </div>
  );
}

export default App;
