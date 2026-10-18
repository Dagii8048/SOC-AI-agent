import os
import sys

# Ensure imports work from parent dir
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from neo4j import GraphDatabase
from graph_queries import investigate_alert, correlate_host_alerts

def main():
    uri = os.environ.get("NEO4J_URI", "bolt://localhost:7687")
    user = os.environ.get("NEO4J_USER", "neo4j")
    password = os.environ.get("NEO4J_PASSWORD", "password")

    try:
        driver = GraphDatabase.driver(uri, auth=(user, password))
        driver.verify_connectivity()
    except Exception as e:
        print(f"Could not connect to Neo4j: {e}")
        return 1

    import seed_fixtures
    seed_fixtures.seed()

    print("\n--- Verifying FX-WIN-KILLCHAIN ---")
    res = investigate_alert(driver, "FX-WIN-100")
    print(res)
    matched_ids = [p["id"] for p in res["matched_patterns"]]
    assert "P-001" in matched_ids, "Missing P-001"
    assert "P-003" in matched_ids, "Missing P-003"
    assert "P-007" in matched_ids, "Missing P-007"
    assert res["kill_chain_detected"] is True, "Kill chain not detected"
    assert res["confidence"] == "CRITICAL", "Confidence should be CRITICAL"
    print("FX-WIN-KILLCHAIN passed.\n")

    print("--- Verifying FX-BENIGN ---")
    res = investigate_alert(driver, "FX-BENIGN-01")
    matched_ids = [p["id"] for p in res["matched_patterns"]]
    assert len(matched_ids) == 0, f"Expected 0 patterns, got {matched_ids}"
    print("FX-BENIGN passed.\n")

    print("--- Verifying FX-LNX-SUDO ---")
    res = investigate_alert(driver, "FX-LNX-200")
    matched_ids = [p["id"] for p in res["matched_patterns"]]
    assert "P-022" in matched_ids, "Missing P-022"
    assert res["confidence"] == "MEDIUM", f"Expected MEDIUM, got {res['confidence']}"
    print("FX-LNX-SUDO passed.\n")

    print("--- Verifying FX-LNX-REVSHELL ---")
    res = investigate_alert(driver, "FX-LNX-300")
    matched_ids = [p["id"] for p in res["matched_patterns"]]
    assert "P-021" in matched_ids, "Missing P-021"
    assert res["confidence"] == "MEDIUM", f"Expected MEDIUM, got {res['confidence']}"
    print("FX-LNX-REVSHELL passed.\n")

    print("--- Verifying Correlation (FX-LNX-SUDO + FX-LNX-REVSHELL) ---")
    # 30 min window is 1800000 ms. They are 5 mins apart (300000 ms)
    res_corr = correlate_host_alerts(driver, "FX-LNX-200", window_ms=1800000)
    assert res_corr["severity"] == "CRITICAL", f"Expected correlation severity CRITICAL, got {res_corr['severity']}"
    assert res_corr["kill_chain"] is not None, "Kill chain should be detected across correlation"
    print("Correlation passed.\n")

    driver.close()
    print("All verifications passed successfully.")
    return 0

if __name__ == "__main__":
    sys.exit(main())
