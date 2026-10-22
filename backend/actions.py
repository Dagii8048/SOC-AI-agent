"""
actions.py
Handles the "One-Click Approve" actions (Section 2.1): the AI can
recommend a containment action, but only a human clicking a button
in the UI actually triggers this code to run.

No real SOAR system exists yet, so SOAR_WEBHOOK_URL points at
httpbin.org/post -- a public test service that just echoes back
whatever's sent to it. Swap this for the real SOAR webhook URL
later; nothing else in this file needs to change.
"""
from dotenv import load_dotenv
load_dotenv()

import os
import requests

SOAR_WEBHOOK_URL = os.environ.get("SOAR_WEBHOOK_URL", "https://httpbin.org/post")

# Only these actions are allowed to execute, and only with these exact
# params. This is the safeguard: nothing outside this list can ever run,
# no matter what an LLM or a bad request tries to send.
ALLOWED_ACTIONS = {
    "isolate_host": ["hostname"],
    "revoke_tokens": ["username"],
}


def execute_action(action: str, params: dict) -> dict:
    if action not in ALLOWED_ACTIONS:
        raise ValueError(f"Unknown or disallowed action: {action}")

    required_params = ALLOWED_ACTIONS[action]
    missing = [p for p in required_params if p not in params]
    if missing:
        raise ValueError(f"Missing required params for {action}: {missing}")

    safe_params = {k: params[k] for k in required_params}

    payload = {"action": action, "params": safe_params}
    response = requests.post(SOAR_WEBHOOK_URL, json=payload, timeout=10)
    response.raise_for_status()

    return {
        "action": action,
        "params": safe_params,
        "status": "sent",
        "soar_response_code": response.status_code,
    }
