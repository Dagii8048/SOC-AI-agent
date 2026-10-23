import AttackGraph from "./AttackGraph";
import "./App.css";

function App() {
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

        <div className="status-badge">
          <span className="status-dot"></span>
          SYSTEM ONLINE
        </div>
      </header>

      <section className="summary-grid">

        <div className="summary-card">
          <span className="summary-label">ACTIVE ALERTS</span>
          <strong>08</strong>
          <span className="summary-info">Requires investigation</span>
        </div>

        <div className="summary-card">
          <span className="summary-label">HIGH RISK</span>
          <strong>03</strong>
          <span className="summary-info">Priority incidents</span>
        </div>

        <div className="summary-card">
          <span className="summary-label">AI ANALYSIS</span>
          <strong>12</strong>
          <span className="summary-info">Investigations analyzed</span>
        </div>

        <div className="summary-card">
          <span className="summary-label">PENDING REVIEW</span>
          <strong>04</strong>
          <span className="summary-info">Awaiting analyst</span>
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

          <AttackGraph />
        </section>

        <section className="panel alert-panel">

          <div className="panel-header">
            <div>
              <span className="panel-label">SECURITY EVENT</span>
              <h2>Active Incident</h2>
            </div>

            <span className="severity-badge">
              HIGH
            </span>
          </div>

          <div className="incident-content">

            <div className="incident-row">
              <span>Incident ID</span>
              <strong>INC-2026-001</strong>
            </div>

            <div className="incident-row">
              <span>Detection</span>
              <strong>Phishing Attack</strong>
            </div>

            <div className="incident-row">
              <span>Source</span>
              <strong>External Attacker</strong>
            </div>

            <div className="incident-row">
              <span>Target</span>
              <strong>Compromised User</strong>
            </div>

            <div className="incident-row">
              <span>Status</span>
              <strong className="investigating">
                Investigating
              </strong>
            </div>

          </div>

        </section>

        <section className="panel ai-panel">

          <div className="panel-header">
            <div>
              <span className="panel-label">AI SECURITY ANALYSIS</span>
              <h2>Investigation Results</h2>
            </div>

            <span className="ai-badge">AI</span>
          </div>

          <div className="ai-result">

            <div className="risk-section">
              <span>Risk Assessment</span>

              <div className="risk-value">
                HIGH
              </div>
            </div>

            <div className="finding">
              <h3>Finding</h3>
              <p>
                The investigation indicates a possible phishing-based
                compromise beginning with an external attacker and
                progressing toward an internal workstation.
              </p>
            </div>

            <div className="finding">
              <h3>Recommended Action</h3>
              <p>
                Isolate the affected workstation, investigate the
                compromised account and review related network activity.
              </p>
            </div>

          </div>

        </section>

        <section className="panel evidence-panel">

          <div className="panel-header">
            <div>
              <span className="panel-label">INVESTIGATION DATA</span>
              <h2>Evidence & Findings</h2>
            </div>
          </div>

          <div className="evidence-list">

            <div className="evidence-item">
              <span className="evidence-icon">01</span>
              <div>
                <strong>Phishing Activity</strong>
                <p>Suspicious phishing event detected.</p>
              </div>
            </div>

            <div className="evidence-item">
              <span className="evidence-icon">02</span>
              <div>
                <strong>User Compromise</strong>
                <p>User account may have been compromised.</p>
              </div>
            </div>

            <div className="evidence-item">
              <span className="evidence-icon">03</span>
              <div>
                <strong>Internal Movement</strong>
                <p>Activity reached the internal workstation.</p>
              </div>
            </div>

            <div className="evidence-item">
              <span className="evidence-icon">04</span>
              <div>
                <strong>Database Exposure</strong>
                <p>Potential path toward internal database.</p>
              </div>
            </div>

          </div>

        </section>

      </main>

      <section className="panel approval-panel">

        <div className="panel-header">
          <div>
            <span className="panel-label">ANALYST DECISION</span>
            <h2>Investigation Approval</h2>
          </div>

          <span className="review-badge">
            HUMAN REVIEW REQUIRED
          </span>
        </div>

        <p className="approval-description">
          Review the AI investigation results and evidence before
          selecting the appropriate analyst decision.
        </p>

        <div className="approval-actions">

          <button className="action-button approve">
            Approve Investigation
          </button>

          <button className="action-button reject">
            Reject Finding
          </button>

          <button className="action-button escalate">
            Escalate Incident
          </button>

        </div>

      </section>

    </div>
  );
}

export default App;
