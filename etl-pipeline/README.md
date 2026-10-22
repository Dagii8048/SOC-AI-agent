ETL: timestamp fix + event mapper
- quick_etl.py: Wazuh times are now read as UTC (they were read as local time, which split one incident into two on non-UTC machines). Adds to_epoch_ms for the events sent to the graph endpoint.
- tests/test_timestamps.py: 4 tests, pass on UTC, Addis Ababa and New York clocks.
- event_mapper.py + tests/test_event_mapper.py: maps Wazuh alerts to the /ingest/events format. Amir, please review it against your contract. A follow-up PR will add handling of malformed records and a level check.
- Note for Dagi: correlated_rag_corpus.json is the old sample output from before the timezone fix. Its chunk IDs change when it is regenerated.
