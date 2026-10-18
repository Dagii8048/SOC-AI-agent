// ============================================================================
// Graph-Based RAG SOC AI Agent — Neo4j Schema Setup
// Role 2 (Graph Engineer, Amir) — Week 1 Deliverable
// Source: Blueprint v2.0, Section 4.3 (with fix from Section 4.3 flag applied)
// ============================================================================

// ----------------------------------------------------------------------------
// CONSTRAINTS
// ----------------------------------------------------------------------------

CREATE CONSTRAINT alert_id_unique IF NOT EXISTS
FOR (a:Alert) REQUIRE a.id IS UNIQUE;

// FIX (Sec 4.3 flag): Process.pid is NOT globally unique. OS process IDs
// recycle constantly -- two unrelated processes on two different hosts (or
// the same host, days apart) can share a PID. A uniqueness constraint on
// pid alone will throw constraint-violation errors the first time two hosts
// report the same PID inside one ETL ingestion window.
//
// Fix: use a synthetic composite key -- hostname + pid + start_timestamp --
// stored as process_uid, and constrain on that instead.
CREATE CONSTRAINT process_uid_unique IF NOT EXISTS
FOR (p:Process) REQUIRE p.process_uid IS UNIQUE;

CREATE CONSTRAINT host_hostname_unique IF NOT EXISTS
FOR (h:Host) REQUIRE h.hostname IS UNIQUE;

CREATE CONSTRAINT user_username_unique IF NOT EXISTS
FOR (u:User) REQUIRE u.username IS UNIQUE;

// ----------------------------------------------------------------------------
// INDEXES
// ----------------------------------------------------------------------------

CREATE INDEX process_timestamp_idx IF NOT EXISTS
FOR (p:Process) ON (p.timestamp);

CREATE INDEX alert_timestamp_idx IF NOT EXISTS
FOR (a:Alert) ON (a.timestamp);

// Supports the MERGE-on-process_uid lookups the ETL pipeline (Role 3) will
// need to do to stay idempotent (see Section 8 flag on CREATE vs MERGE).
CREATE INDEX process_uid_idx IF NOT EXISTS
FOR (p:Process) ON (p.process_uid);

// ----------------------------------------------------------------------------
// NOTE FOR ETL (Role 3): how to build process_uid
// ----------------------------------------------------------------------------
// process_uid = f"{hostname}:{pid}:{start_timestamp}"
// Generate this in Python before the MERGE, e.g.:
//   MERGE (p:Process {process_uid: $process_uid})
//   ON CREATE SET p.pid = $pid, p.name = $name, p.path = $path,
//                 p.hash = $hash, p.timestamp = $timestamp

// ----------------------------------------------------------------------------
// SCHEMA GAPS FOUND WHILE BUILDING THE PATTERN LIBRARY (see pattern_library.py)
// ----------------------------------------------------------------------------
// The properties below are referenced by one or more of the 20 attack
// patterns but are NOT listed in Section 4.1's node property tables.
// Recommend adding them to the ETL's node-creation step before Week 2:
//
//   Process.args              -- command-line args (P-010, P-011, P-015, P-016)
//   File.extension             -- file extension (P-006, ransomware detection)
//   User.failed_logins         -- int, rolling counter (P-018, password spraying)
//   User.last_failed           -- epoch timestamp of last failed login (P-018)
//
// Also worth a team discussion: several original patterns (old P-002, P-009,
// P-018) describe host- or user-level anomalies with no attached Process,
// meaning they don't naturally hang off Alert-[:TRIGGERED_BY]->Process, the
// only path the schema currently defines from Alert. If host/user-level
// alerts (no process attribution) are expected, consider adding a second
// relationship, e.g. Alert-[:DETECTED_ON]->Host or Alert-[:DETECTED_ON]->User,
// rather than forcing every alert through a Process node.
