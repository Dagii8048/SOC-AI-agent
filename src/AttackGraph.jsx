import { useEffect, useRef, useState } from "react";
import cytoscape from "cytoscape";
import "./AttackGraph.css";

// One colour per kind of node in the graph.
const TYPE_COLORS = {
  Alert: "#dc2626",
  Process: "#2563eb",
  Host: "#16a34a",
  User: "#9333ea",
  Network: "#d97706",
  File: "#0d9488",
  Unknown: "#64748b",
};

// Properties that are already shown elsewhere or are only for drawing.
const HIDDEN_PROPS = ["id", "label", "type"];
const MAX_VALUE_LENGTH = 300;

function showValue(value) {
  const text = typeof value === "string" ? value : JSON.stringify(value);
  return text.length > MAX_VALUE_LENGTH ? `${text.slice(0, MAX_VALUE_LENGTH)}…` : text;
}

function AttackGraph({ graph, loading, error }) {
  const graphRef = useRef(null);
  const [selectedNode, setSelectedNode] = useState(null);

  const hasGraph = Boolean(graph && graph.nodes && graph.nodes.length > 0);

  // Draw the graph whenever a new one arrives.
  useEffect(() => {
    setSelectedNode(null);
    if (!hasGraph) return undefined;

    // Cytoscape throws if an edge points at a node that is not there.
    const nodeIds = new Set(graph.nodes.map((n) => n.data.id));
    const edges = graph.edges.filter(
      (e) => nodeIds.has(e.data.source) && nodeIds.has(e.data.target)
    );

    const cy = cytoscape({
      container: graphRef.current,
      elements: [...graph.nodes, ...edges],
      layout: {
        name: "breadthfirst",
        directed: true,
        padding: 40,
        roots: '[type = "Alert"]',
      },
      style: [
        {
          selector: "node",
          style: {
            "background-color": TYPE_COLORS.Unknown,
            label: "data(label)",
            color: "#ffffff",
            "text-valign": "center",
            "text-halign": "center",
            "font-size": "11px",
            "text-wrap": "ellipsis",
            "text-max-width": "100px",
            width: "115px",
            height: "50px",
            shape: "round-rectangle",
          },
        },
        ...Object.entries(TYPE_COLORS).map(([type, color]) => ({
          selector: `node[type = "${type}"]`,
          style: { "background-color": color },
        })),
        {
          selector: "edge",
          style: {
            width: 2.5,
            "line-color": "#94a3b8",
            "target-arrow-color": "#94a3b8",
            "target-arrow-shape": "triangle",
            "curve-style": "bezier",
            label: "data(type)",
            "font-size": "9px",
            color: "#94a3b8",
            "text-rotation": "autorotate",
            "text-background-color": "#020617",
            "text-background-opacity": 1,
            "text-background-padding": "2px",
          },
        },
        {
          selector: "node:selected",
          style: {
            "border-width": 4,
            "border-color": "#f59e0b",
          },
        },
      ],
    });

    cy.on("tap", "node", (event) => {
      const data = event.target.data();
      const props = Object.entries(data).filter(([key]) => !HIDDEN_PROPS.includes(key));
      setSelectedNode({ id: data.id, label: data.label, type: data.type, props });
    });

    return () => {
      cy.destroy();
    };
  }, [graph, hasGraph]);

  const typesInGraph = hasGraph
    ? [...new Set(graph.nodes.map((n) => n.data.type || "Unknown"))]
    : [];

  let overlay = null;
  if (loading) overlay = "Loading attack graph...";
  else if (error) overlay = error;
  else if (!graph) overlay = "Select an alert to see its attack graph.";
  else if (!hasGraph) overlay = "This alert has no graph data.";

  return (
    <div className="attack-graph-container">
      <div className="graph-wrap">
        <div ref={graphRef} className="cytoscape-graph"></div>
        {overlay && (
          <div className={`graph-overlay${error ? " graph-overlay-error" : ""}`}>{overlay}</div>
        )}
      </div>

      {typesInGraph.length > 0 && (
        <div className="graph-legend">
          {typesInGraph.map((type) => (
            <span key={type} className="legend-item">
              <span
                className="legend-dot"
                style={{ background: TYPE_COLORS[type] || TYPE_COLORS.Unknown }}
              ></span>
              {type}
            </span>
          ))}
        </div>
      )}

      {selectedNode && (
        <div className="selected-node-panel">
          <h3>Node Details</h3>

          <p>
            <strong>Type:</strong> {selectedNode.type}
          </p>
          <p>
            <strong>Name:</strong> {selectedNode.label}
          </p>

          {selectedNode.props.map(([key, value]) => (
            <p key={key} className="node-prop">
              <strong>{key}:</strong> <code>{showValue(value)}</code>
            </p>
          ))}
        </div>
      )}
    </div>
  );
}

export default AttackGraph;
