import json
import os
import glob
from neo4j import GraphDatabase

def seed():
    uri = os.environ.get("NEO4J_URI", "bolt://localhost:7687")
    user = os.environ.get("NEO4J_USER", "neo4j")
    password = os.environ.get("NEO4J_PASSWORD", "password")

    # We will simulate pushing them through our loader
    import sys
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from graph_loader import load_event

    driver = GraphDatabase.driver(uri, auth=(user, password))
    with driver.session(database=os.environ.get("NEO4J_DATABASE") or None) as session:
        # Clear existing FX- alerts and ONLY the processes strictly triggered by them.
        # We must NOT delete shared Hosts or Users, nor traverse into other Alerts.
        session.run("""
        MATCH (a:Alert)
        WHERE a.id STARTS WITH 'FX-'
        OPTIONAL MATCH (a)-[:TRIGGERED_BY]->(p:Process)
        OPTIONAL MATCH (p)-[:SPAWNED*1..5]->(child:Process)
        DETACH DELETE a, p, child
        """)

        fixtures_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "fixtures")
        for fix_file in glob.glob(os.path.join(fixtures_dir, "*.json")):
            print(f"Loading {fix_file}...")
            with open(fix_file, 'r') as f:
                data = json.load(f)
                events = data.get("events", [])
                for evt in events:
                    load_event(session, evt)

    driver.close()
    print("Fixtures loaded successfully.")

if __name__ == "__main__":
    seed()
