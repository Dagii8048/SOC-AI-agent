"""
agent.py
Role 1 (Orchestrator) — LangGraph Agent Pipeline
"""
import os
import json
import urllib.request
import urllib.error
import sys
import socket
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
# Ollama settings come from .env (see .env.example), not from the code.
# ---------------------------------------------------------------------------
def _int_env(name, default):
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default

OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "http://localhost:11434").rstrip("/")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "llama3.1:8b")
OLLAMA_TIMEOUT = _int_env("OLLAMA_TIMEOUT_SECONDS", 120)

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
    model_path=os.path.join(ml_rag_path, "fp_classifier.pkl"), 
    encoder_path=os.path.join(ml_rag_path, "alert_type_encoder.pkl")
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
    # The caller (backend/tasks.py) passes the real investigation result in
    # state["graph_context"]. We keep it exactly as given: no mock data and
    # no cutting it short. The caller decides how much to send.
    graph_context = state.get("graph_context")
    if graph_context:
        print("[AGENT] Using the graph context provided by the caller.")
        return {"graph_context": graph_context}

    print("[AGENT] No graph context was provided for this alert.")
    return {"graph_context": {"note": "No graph data was provided for this alert."}}

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

    ## MACHINE LEARNING CLASSIFICATION
    The XGBoost classifier predicts: {state['fp_prediction']['prediction']}
    The ML Confidence is: {ml_confidence}

    ## TASK
    Provide a JSON response with exactly these keys:
    - "executive_summary": A 1-sentence plain English explanation.
    - "threat_level": Base this on the ML Classification provided above. If the ML predicts "MALICIOUS", use "HIGH" or "CRITICAL". If "BENIGN", use "LOW".
    - "mitre_techniques": A list of strings (e.g., ["T1059.001"]).
    - "recommendations": A list of up to 3 specific actions.

    Output ONLY valid JSON.
    """

    url = f"{OLLAMA_HOST}/api/generate"
    data = {
        "model": OLLAMA_MODEL,
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
        with urllib.request.urlopen(req, timeout=OLLAMA_TIMEOUT) as response:
            result = json.loads(response.read().decode('utf-8'))
            llm_output = result['response']
            parsed_json = json.loads(llm_output)
            return {"final_briefing": parsed_json}
            
    except (TimeoutError, socket.timeout):
        print(f"[ERROR] Ollama did not answer within {OLLAMA_TIMEOUT} seconds.")
        return {"final_briefing": {"error": f"Ollama timed out after {OLLAMA_TIMEOUT} seconds."}}
    except urllib.error.URLError as e:
        if isinstance(e.reason, (TimeoutError, socket.timeout)):
            print(f"[ERROR] Ollama did not answer within {OLLAMA_TIMEOUT} seconds.")
            return {"final_briefing": {"error": f"Ollama timed out after {OLLAMA_TIMEOUT} seconds."}}
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
        "description": test_alert["description"],
        "graph_context": {
            "matched_patterns": [{"id": "P-004", "name": "C2 Beaconing", "mitre": "T1071.001"}],
            "kill_chain_detected": False,
        },
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