"""
repo_paths.py
Teammates' code lives in sibling folders (graph/, orchestrator/), not inside
backend/. Python only looks in a few places when you write `import x`, so this
file adds those sibling folders to the list. Import it FIRST, before importing
anything from graph/ or orchestrator/.
"""
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
GRAPH_DIR = REPO_ROOT / "graph"
ORCHESTRATOR_DIR = REPO_ROOT / "orchestrator"

for folder in (GRAPH_DIR, ORCHESTRATOR_DIR):
    if str(folder) not in sys.path:
        sys.path.append(str(folder))
