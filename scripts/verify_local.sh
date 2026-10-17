#!/bin/bash
# Mock script if Docker is not available.
echo "Cypher has not been verified in a live DB in this automated script, as it depends on local Docker."
echo "However, you can run pytest to see mocked results."
pytest tests/
