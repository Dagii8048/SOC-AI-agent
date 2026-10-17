# Integration Notes

## Beka
- Send structured events to `/ingest/events` alongside the narrative text.
- Needs host, pid, parent pid, cmdline, user, dest ip/port and file path.
- Please decide on the correlation window (15 min vs 30 min).

## Tale
- Mount the router: `app.include_router(ingest_router.router)`
- Add CORS for `http://localhost:5173`
- Unmatched alerts return explicit `not-found`, not LOW or {"error"}.
- `investigate_alert` is shared.
- Note: `/actions/execute` has no auth and posts hostnames/usernames to httpbin.org.

## Wakjira
- Use `get_alert_subgraph` shape and map node types to your labels.

## Teferi
- See input shape in ETL_GRAPH_CONTRACT.md.
- Please sanitize log strings before they reach the prompt.

## Open Decisions (for me)
- Alerts with no process may need Alert-[:DETECTED_ON]->Host|User.
- User keyed by username alone merges Linux "root" across hosts (propose user_uid).
- Severity mapping.
- Correlation window.
