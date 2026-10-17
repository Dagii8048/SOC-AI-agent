import json
import glob
from neo4j import GraphDatabase
from graph_loader import load_event

URI = "bolt://localhost:7687"
USER = "neo4j"
PASSWORD = "password"

def run():
    driver = GraphDatabase.driver(URI, auth=(USER, PASSWORD))
    files = glob.glob("fixtures/*.json")
    for f in files:
        with open(f, "r") as file:
            event = json.load(file)
            with driver.session() as session:
                load_event(session, event)
    driver.close()

if __name__ == "__main__":
    run()
