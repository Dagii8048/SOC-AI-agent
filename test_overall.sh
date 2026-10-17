#!/bin/bash
source .venv/bin/activate
PYTHONPATH=. pytest tests/
