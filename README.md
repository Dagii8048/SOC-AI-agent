ETL: timestamp fix + event mapper
- quick_etl.py: Wazuh times are now read as UTC (they were read as local time, which split one incident into two on non-UTC machines). Adds to_epoch_ms for the events sent to the graph endpoint.
- tests/test_timestamps.py: 4 tests, pass on UTC, Addis Ababa and New York clocks.
- event_mapper.py + tests/test_event_mapper.py: maps Wazuh alerts to the /ingest/events format. Amir, please review it against your contract. A follow-up PR will add handling of malformed records and a level check.
- Note for Dagi: correlated_rag_corpus.json is the old sample output from before the timezone fix. Its chunk IDs change when it is regenerated.
- 

## ETL pipeline (etl/)

This folder contains `quick_etl.py`, `event_mapper.py`, `dispatcher.py` (when it lands), `sample_*.json`, and `tests/`.

To run the tests:
```bash
cd etl && python -m unittest discover -s tests
```

To run the ETL:
```bash
cd etl && python quick_etl.py
```

The dispatcher dry-run command (available once the dispatcher PR is merged):
```bash
cd etl && python dispatcher.py --wazuh sample_wazuh.json --osquery sample_osquery.json --dry-run
```

**Note**: `INGEST_URL` and `INGEST_API_KEY` come only from environment variables and must never be committed or pasted in chats. `rejected_events.jsonl` is a local log that is not committed.
