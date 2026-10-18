#!/bin/bash
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
export PYTHONPATH="$(dirname "$DIR")"

echo "Applying schema..."
cypher-shell -u ${NEO4J_USER:-neo4j} -p ${NEO4J_PASSWORD:-password} -a ${NEO4J_URI:-bolt://localhost:7687} -f "$DIR/../neo4j_schema_setup.cypher" || echo "Warning: cypher-shell not found or failed, proceeding..."

echo "Running python verification script..."
python3 "$DIR/verify_local.py" || { echo "Verification failed!"; }
