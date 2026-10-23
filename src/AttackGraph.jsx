import { useEffect, useRef, useState } from "react";
import cytoscape from "cytoscape";
import { investigateNode } from "./api";
import "./AttackGraph.css";

function AttackGraph() {
  const graphRef = useRef(null);

  // Selected graph node
  const [selectedNode, setSelectedNode] = useState(null);

  // Analyst decision
  const [approvalStatus, setApprovalStatus] = useState(null);

  // Backend investigation
  const [investigationResult, setInvestigationResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  // --------------------------------------------------
  // Demo investigation data
  // --------------------------------------------------

  const nodeDetails = {
    attacker: {
      type: "External Threat",
      description:
        "External entity associated with suspicious activity.",
      severity: "HIGH",
      alert: "Suspicious External Activity",
      evidence:
        "Repeated connection attempts from an external source.",
      technique: "T1046",
      recommendation:
        "Investigate the source IP and related network activity.",
      aiFinding:
        "The activity indicates a possible external reconnaissance attempt against the environment.",
      aiConfidence: "91%",
      aiAction:
        "Investigate the source IP and review related network connections.",
    },

    phishing: {
      type: "Phishing Activity",
      description:
        "Suspicious phishing activity detected.",
      severity: "HIGH",
      alert: "Suspicious Phishing Email",
      evidence:
        "User interaction with a suspicious email or malicious link.",
      technique: "T1566",
      recommendation:
        "Investigate the phishing source and affected user.",
      aiFinding:
        "The observed activity is consistent with a possible phishing attack targeting the user.",
      aiConfidence: "94%",
      aiAction:
        "Review the email source, URL, and affected user activity.",
    },

    user: {
      type: "Compromised User",
      description:
        "User account associated with suspicious activity.",
      severity: "HIGH",
      alert: "Possible Account Compromise",
      evidence:
        "Unusual authentication or account activity was observed.",
      technique: "T1078",
      recommendation:
        "Verify the user's activity and account status.",
      aiFinding:
        "The user's account shows indicators that may be consistent with credential compromise.",
      aiConfidence: "92%",
      aiAction:
        "Verify the user's recent authentication activity and account status.",
    },

    workstation: {
      type: "Endpoint",
      description:
        "Workstation associated with the security event.",
      severity: "HIGH",
      alert: "Suspicious PowerShell Activity",
      evidence:
        "PowerShell execution was observed on the workstation.",
      technique: "T1059.001",
      recommendation:
        "Investigate the process tree and PowerShell activity.",
      aiFinding:
        "The workstation shows suspicious PowerShell activity that may require further investigation.",
      aiConfidence: "93%",
      aiAction:
        "Review the PowerShell process tree and related endpoint events.",
    },

    server: {
      type: "Internal Server",
      description:
        "Internal server connected to the observed attack path.",
      severity: "CRITICAL",
      alert: "Possible Lateral Movement",
      evidence:
        "Communication from a compromised workstation to an internal server.",
      technique: "T1021",
      recommendation:
        "Investigate possible lateral movement and authentication events.",
      aiFinding:
        "The connection pattern may indicate lateral movement from the compromised workstation.",
      aiConfidence: "89%",
      aiAction:
        "Review authentication logs and network connections involving the server.",
    },

    database: {
      type: "Database",
      description:
        "Database reached through the observed attack path.",
      severity: "CRITICAL",
      alert: "Possible Unauthorized Database Access",
      evidence:
        "Database access occurred after the observed attack path.",
      technique: "T1530",
      recommendation:
        "Check database access logs for unauthorized activity.",
      aiFinding:
        "The observed attack path indicates possible unauthorized access to the database.",
      aiConfidence: "90%",
      aiAction:
        "Review database access logs and verify the affected account.",
    },
  };

  // --------------------------------------------------
  // Create Cytoscape attack graph
  // --------------------------------------------------

  useEffect(() => {
    const cy = cytoscape({
      container: graphRef.current,

      elements: [
        {
          data: {
            id: "attacker",
            label: "Attacker",
          },
        },

        {
          data: {
            id: "phishing",
            label: "Phishing",
          },
        },

        {
          data: {
            id: "user",
            label: "Compromised User",
          },
        },

        {
          data: {
            id: "workstation",
            label: "Workstation",
          },
        },

        {
          data: {
            id: "server",
            label: "Internal Server",
          },
        },

        {
          data: {
            id: "database",
            label: "Database",
          },
        },

        {
          data: {
            id: "edge1",
            source: "attacker",
            target: "phishing",
          },
        },

        {
          data: {
            id: "edge2",
            source: "phishing",
            target: "user",
          },
        },

        {
          data: {
            id: "edge3",
            source: "user",
            target: "workstation",
          },
        },

        {
          data: {
            id: "edge4",
            source: "workstation",
            target: "server",
          },
        },

        {
          data: {
            id: "edge5",
            source: "server",
            target: "database",
          },
        },
      ],

      layout: {
        name: "breadthfirst",
        directed: true,
        padding: 40,
      },

      style: [
        {
          selector: "node",

          style: {
            "background-color": "#2563eb",
            label: "data(label)",
            color: "#ffffff",
            "text-valign": "center",
            "text-halign": "center",
            "font-size": "12px",
            width: "110px",
            height: "55px",
          },
        },

        {
          selector: "edge",

          style: {
            width: 3,
            "line-color": "#94a3b8",
            "target-arrow-color": "#94a3b8",
            "target-arrow-shape": "triangle",
            "curve-style": "bezier",
          },
        },

        {
          selector: "node:selected",

          style: {
            "background-color": "#f59e0b",
            "border-width": 4,
            "border-color": "#ffffff",
          },
        },
      ],
    });

    // --------------------------------------------------
    // Detect node selection
    // --------------------------------------------------

    cy.on("tap", "node", (event) => {
      const node = event.target;
      const id = node.id();

      setSelectedNode({
        id: id,
        label: node.data("label"),
        details: nodeDetails[id],
      });

      // Reset previous investigation
      setInvestigationResult(null);
      setError(null);

      // Reset previous analyst decision
      setApprovalStatus(null);
    });

    // Cleanup Cytoscape
    return () => {
      cy.destroy();
    };
  }, []);

  // --------------------------------------------------
  // Investigate selected node through FastAPI
  // --------------------------------------------------

  const handleInvestigate = async () => {
    if (!selectedNode) {
      return;
    }

    setLoading(true);
    setError(null);
    setInvestigationResult(null);
    setApprovalStatus(null);

    try {
      const result = await investigateNode(selectedNode.id);

      setInvestigationResult(result);
    } catch (err) {
      console.error("Investigation error:", err);

      setError(
        "Unable to connect to the investigation backend."
      );
    } finally {
      setLoading(false);
    }
  };

  // --------------------------------------------------
  // Analyst approves investigation
  // --------------------------------------------------

  const handleApprove = () => {
    setApprovalStatus("approved");
  };

  // --------------------------------------------------
  // Analyst rejects investigation
  // --------------------------------------------------

  const handleReject = () => {
    setApprovalStatus("rejected");
  };

  // --------------------------------------------------
  // Get confidence value
  // --------------------------------------------------

  const getConfidence = () => {
    if (
      investigationResult &&
      investigationResult.ai_investigation &&
      investigationResult.ai_investigation.confidence !==
        undefined
    ) {
      return Math.round(
        investigationResult.ai_investigation.confidence * 100
      );
    }

    return selectedNode
      ? selectedNode.details.aiConfidence
      : "N/A";
  };

  // --------------------------------------------------
  // UI
  // --------------------------------------------------

  return (
    <div className="attack-graph-container">

      {/* ==========================================
          ATTACK GRAPH
      =========================================== */}

      <div
        ref={graphRef}
        className="cytoscape-graph"
      ></div>


      {/* ==========================================
          SELECTED NODE
      =========================================== */}

      {selectedNode && (
        <div className="selected-node-panel">

          <h3>Investigation Details</h3>

          <p>
            <strong>Name:</strong>{" "}
            {selectedNode.label}
          </p>

          <p>
            <strong>ID:</strong>{" "}
            {selectedNode.id}
          </p>

          <p>
            <strong>Type:</strong>{" "}
            {selectedNode.details.type}
          </p>

          <p>
            <strong>Alert:</strong>{" "}
            {selectedNode.details.alert}
          </p>

          <p>
            <strong>Evidence:</strong>{" "}
            {selectedNode.details.evidence}
          </p>

          <p>
            <strong>Description:</strong>{" "}
            {selectedNode.details.description}
          </p>

          <p>
            <strong>Severity:</strong>{" "}
            <span className="severity-high">
              {selectedNode.details.severity}
            </span>
          </p>

          <p>
            <strong>MITRE Technique:</strong>{" "}
            {selectedNode.details.technique}
          </p>


          {/* ========================================
              RECOMMENDATION
          ========================================= */}

          <div className="investigation-recommendation">

            <strong>Recommendation</strong>

            <p>
              {selectedNode.details.recommendation}
            </p>

          </div>


          {/* ========================================
              INVESTIGATE BUTTON
          ========================================= */}

          <button
            className="investigate-button"
            onClick={handleInvestigate}
            disabled={loading}
          >
            {loading
              ? "Investigating..."
              : "Investigate with AI"}
          </button>


          {/* ========================================
              BACKEND ERROR
          ========================================= */}

          {error && (
            <div className="investigation-error">
              {error}
            </div>
          )}


          {/* ========================================
              AI INVESTIGATION RESULT
          ========================================= */}

          <div className="ai-investigation-panel">

            <h3>AI Investigation Result</h3>

            <p>
              <strong>Finding:</strong>
            </p>

            <p>
              {investigationResult?.ai_investigation?.finding ||
                selectedNode.details.aiFinding}
            </p>


            <p>
              <strong>AI Confidence:</strong>{" "}
              <span className="ai-confidence">
                {getConfidence()}
                {typeof getConfidence() === "number"
                  ? "%"
                  : ""}
              </span>
            </p>


            <p>
              <strong>Recommended Action:</strong>
            </p>

            <p>
              {investigationResult
                ?.ai_investigation
                ?.recommended_action ||
                selectedNode.details.aiAction}
            </p>

          </div>


          {/* ========================================
              REAL BACKEND RESULT
          ========================================= */}

          {investigationResult && (
            <div className="backend-result-panel">

              <h3>
                Backend Investigation Result
              </h3>

              {investigationResult.node_id && (
                <p>
                  <strong>Node ID:</strong>{" "}
                  {investigationResult.node_id}
                </p>
              )}

              {investigationResult.entity && (
                <>
                  <p>
                    <strong>Entity:</strong>{" "}
                    {investigationResult.entity.name}
                  </p>

                  <p>
                    <strong>Entity Type:</strong>{" "}
                    {investigationResult.entity.type}
                  </p>

                  <p>
                    <strong>Backend Severity:</strong>{" "}
                    {investigationResult.entity.severity}
                  </p>
                </>
              )}

              {investigationResult.mitre && (
                <>
                  <p>
                    <strong>MITRE Technique:</strong>{" "}
                    {investigationResult.mitre.technique_id}
                  </p>

                  <p>
                    <strong>Technique Name:</strong>{" "}
                    {investigationResult.mitre.technique_name}
                  </p>
                </>
              )}

            </div>
          )}


          {/* ========================================
              ANALYST APPROVAL
          ========================================= */}

          <div className="analyst-approval-panel">

            <h3>Analyst Approval</h3>

            <p>
              Review the AI investigation result before
              making an analyst decision.
            </p>


            <div className="approval-buttons">

              <button
                className="approve-button"
                onClick={handleApprove}
                disabled={loading}
              >
                Approve Investigation
              </button>


              <button
                className="reject-button"
                onClick={handleReject}
                disabled={loading}
              >
                Reject / Review Again
              </button>

            </div>


            {/* Approved */}

            {approvalStatus === "approved" && (
              <div className="approval-result approved">
                Analyst Decision: APPROVED
              </div>
            )}


            {/* Rejected */}

            {approvalStatus === "rejected" && (
              <div className="approval-result rejected">
                Analyst Decision: REJECTED — Review Required
              </div>
            )}

          </div>

        </div>
      )}

    </div>
  );
}

export default AttackGraph;
