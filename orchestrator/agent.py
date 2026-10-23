"""
agent.py
Role 1 (Orchestrator) — LangGraph Agent Pipeline
"""
import os
import json
import urllib.request
import urllib.error
import sys
from typing import TypedDict, Optional

from pathlib import Path

# Dynamically find the ml-rag folder regardless of where the repo is cloned
repo_root = Path(__file__).resolve().parent.parent
ml_rag_path = str(repo_root / "ml-rag")
sys.path.append(ml_rag_path)

from classifier_inference import FPClassifier
from rag_pipeline import search_similar
from langgraph.graph import StateGraph, END

# ---------------------------------------------------------------------------
# 1. DEFINE THE LANGGRAPH STATE
# ---------------------------------------------------------------------------
class AgentState(TypedDict):
    alert_id: str
    alert_type: str
    severity: str
    description: str
    fp_prediction: Optional[dict]
    rag_context: Optional[list]
    graph_context: Optional[dict]
    final_briefing: Optional[dict]

# ---------------------------------------------------------------------------
# 2. INITIALIZE MODELS
# ---------------------------------------------------------------------------
print("[INIT] Loading FP Classifier...")
# Note: We point to the .pkl files in the ml-rag folder
clf = FPClassifier(
    model_path="../ml-rag/fp_classifier.pkl", 
    encoder_path="../ml-rag/alert_type_encoder.pkl"
)

# ---------------------------------------------------------------------------
# 3. DEFINE THE NODES
# ---------------------------------------------------------------------------
def check_false_positive(state: AgentState):
    print(f"[AGENT] Running FP Classifier for {state['alert_id']}...")
    result = clf.predict(
        alert_type=state['alert_type'],
        severity=state['severity'],
        description=state['description']
    )
    return {"fp_prediction": result}

def fetch_graph_context(state: AgentState):
    print(f"[AGENT] Fetching Neo4j graph context (Mocked)...")
    # In reality, you'd query Neo4j here using Amir's Cypher
    mock_graph = {
        "nodes": ["User:Bob (Admin)", "Process:powershell.exe", "Network:5.6.7.8"],
        "relationships": ["Bob OWNS powershell", "powershell CONNECTED_TO 5.6.7.8"],
        "matched_patterns": ["P-001 (Phishing)", "P-004 (C2 Beaconing)"]
    }
    graph_str = json.dumps(mock_graph)
    truncated_graph_str = graph_str[:2000]  # Max 2000 characters

    return {"graph_context": truncated_graph_str}

def fetch_rag_context(state: AgentState):
    print(f"[AGENT] Retrieving RAG context from Qdrant...")
    query = f"{state['alert_type']}: {state['description']}"
    # This calls YOUR function from ml-rag/rag_pipeline.py
    results = search_similar(query, top_k=3)
    return {"rag_context": results}

def generate_llm_briefing(state: AgentState):
    print(f"[AGENT] Generating LLM Briefing via Ollama...")
    
    ml_confidence = state['fp_prediction']['confidence']
    if state['fp_prediction']['auto_close']:
        print("[AGENT] Auto-closing alert (FP Classifier confidence > 95%)")
        return {"final_briefing": {"summary": "AUTO-CLOSED: Model predicted benign."}}

    rag_text = ""
    for inc in state['rag_context']:
        rag_text += f"- [{inc['resolution']}] {inc['description']}\n"

    prompt = f"""
    You are a Senior SOC Analyst AI Assistant.
    Your goal is to help the human analyst make a decision in under 10 seconds.

    ## ALERT DETAILS
    - **Type:** {state['alert_type']}
    - **Severity:** {state['severity']}
    - **Description:** {state['description']}

    ## ATTACK GRAPH (Live Data)
    {json.dumps(state['graph_context'], indent=2)}

    ## SIMILAR PAST INCIDENTS (RAG)
    {rag_text}

    ## TASK
    Provide a JSON response with exactly these keys:
    - "executive_summary": A 1-sentence plain English explanation.
    - "threat_level": "CRITICAL", "HIGH", "MEDIUM", or "LOW".
    - "mitre_techniques": A list of strings (e.g., ["T1059.001"]).
    - "recommendations": A list of up to 3 specific actions.

    Output ONLY valid JSON.
    """

    url = "http://localhost:11434/api/generate"
    data = {
        "model": "llama3.1:8b",
        "prompt": prompt,
        "stream": False,
        "format": "json"
    }
    
    req = urllib.request.Request(
        url, 
        data=json.dumps(data).encode('utf-8'), 
        headers={'Content-Type': 'application/json'}
    )

    try:
        with urllib.request.urlopen(req) as response:
            result = json.loads(response.read().decode('utf-8'))
            llm_output = result['response']
            parsed_json = json.loads(llm_output)
            return {"final_briefing": parsed_json}
            
    except urllib.error.URLError as e:
        print(f"[ERROR] Could not connect to Ollama: {e}")
        return {"final_briefing": {"error": "Ollama is not running."}}
    except json.JSONDecodeError:
        print(f"[ERROR] LLM did not return valid JSON.")
        return {"final_briefing": {"error": "LLM formatting failed."}}

# ---------------------------------------------------------------------------
# 4. BUILD THE GRAPH
# ---------------------------------------------------------------------------
workflow = StateGraph(AgentState)
workflow.add_node("check_fp", check_false_positive)
workflow.add_node("fetch_graph", fetch_graph_context)
workflow.add_node("fetch_rag", fetch_rag_context)
workflow.add_node("generate", generate_llm_briefing)

workflow.set_entry_point("check_fp")
workflow.add_edge("check_fp", "fetch_graph")
workflow.add_edge("fetch_graph", "fetch_rag")
workflow.add_edge("fetch_rag", "generate")
workflow.add_edge("generate", END)

app = workflow.compile()

# ---------------------------------------------------------------------------
# 5. TEST IT
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    print("="*60)
    print("LANGGRAPH ORCHESTRATOR TEST")
    print("="*60)
    
    test_alert = {
        "alert_id": "A-123",
        "alert_type": "C2 Beaconing",
        "severity": "High",
        "description": "PowerShell established HTTPS connection to unknown IP every 30 seconds"
    }
    
    print(f"Input Alert: {test_alert['alert_id']}\n")
    
    initial_state = {
        "alert_id": test_alert["alert_id"],
        "alert_type": test_alert["alert_type"],
        "severity": test_alert["severity"],
        "description": test_alert["description"]
    }
    
    result = app.invoke(initial_state)
    
    print("\n" + "="*60)
    print("FINAL ANALYST BRIEFING")
    print("="*60)
    
    briefing = result['final_briefing']
    if isinstance(briefing, dict) and "error" not in briefing:
        print(f"Summary:       {briefing.get('executive_summary')}")
        print(f"Threat Level:  {briefing.get('threat_level')}")
        print(f"MITRE:         {', '.join(briefing.get('mitre_techniques', []))}")
        print(f"\nRecommendations:")
        for rec in briefing.get('recommendations', []):
            print(f" - {rec}")
    else:
        print(briefing)