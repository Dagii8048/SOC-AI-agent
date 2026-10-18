#!/bin/bash
export PYTHONPATH=$(dirname $(dirname $(readlink -f $0)))

python3 -c '
import os
import sys
from neo4j import GraphDatabase
from pattern_library import match_patterns
from pattern_evaluator import evaluate_patterns
from graph_queries import investigate_alert

uri = os.environ.get("NEO4J_URI", "bolt://localhost:7687")
user = os.environ.get("NEO4J_USER", "neo4j")
password = os.environ.get("NEO4J_PASSWORD", "password")
driver = GraphDatabase.driver(uri, auth=(user, password))

print("\n--- Verifying FX-WIN-KILLCHAIN ---")
res = investigate_alert(driver, "AL-WIN-100")
print(f"Kill Chain Detected: {res[\"kill_chain_detected\"]}")
print(f"Kill Chain Name: {res[\"kill_chain_name\"]}")
print(f"Matched Patterns: {[p[\"id\"] for p in res[\"matched_patterns\"]]} \n")

print("--- Verifying FX-LNX-SUDO ---")
res = investigate_alert(driver, "AL-LNX-200")
print(f"Matched Patterns: {[p[\"id\"] for p in res[\"matched_patterns\"]]} \n")

print("--- Verifying FX-LNX-REVSHELL ---")
res = investigate_alert(driver, "AL-LNX-300")
print(f"Matched Patterns: {[p[\"id\"] for p in res[\"matched_patterns\"]]} \n")

print("--- Verifying FX-BENIGN ---")
res = investigate_alert(driver, "AL-BENIGN-01")
print(f"Matched Patterns: {[p[\"id\"] for p in res[\"matched_patterns\"]]} \n")

driver.close()
'
