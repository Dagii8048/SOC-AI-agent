import json
import logging
import os
import threading
import unittest
import tempfile
from http.server import HTTPServer, BaseHTTPRequestHandler
from unittest.mock import patch, MagicMock

from dispatcher import (
    truncate_event,
    truncate_text,
    split_batches,
    send_batch,
    parse_response,
    dispatch
)

# Test setup
class FakeServerHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass # Suppress logging

    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length).decode('utf-8')

        # Test server tracks requests for assertions
        self.server.requests.append({
            "path": self.path,
            "headers": self.headers,
            "body": body
        })

        if not self.headers.get('X-API-Key'):
            self.send_response(401)
            self.end_headers()
            self.wfile.write(b'{"error": "Unauthorized"}')
            return

        req_data = json.loads(body)
        events = req_data.get("events", [])

        response_behavior = self.server.response_behavior.pop(0) if self.server.response_behavior else {"status": 200, "body": {"accepted": 0, "rejected": []}}

        self.send_response(response_behavior["status"])
        self.send_header('Content-Type', 'application/json')
        self.end_headers()

        if response_behavior.get("body") is not None:
            self.wfile.write(json.dumps(response_behavior["body"]).encode('utf-8'))

class TestDispatcherBase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = HTTPServer(('127.0.0.1', 0), FakeServerHandler)
        cls.server.requests = []
        cls.server.response_behavior = []

        cls.server_thread = threading.Thread(target=cls.server.serve_forever)
        cls.server_thread.daemon = True
        cls.server_thread.start()

        cls.url = f"http://127.0.0.1:{cls.server.server_port}/ingest/events"
        cls.api_key = "test_key_123"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.server_thread.join()

    def setUp(self):
        self.server.requests.clear()
        self.server.response_behavior.clear()

        # Use temp directory for tests
        self.temp_dir = tempfile.TemporaryDirectory()
        self.log_path = os.path.join(self.temp_dir.name, "test_rejected_events.jsonl")

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_success(self):
        events = [{"id": 1}, {"id": 2}]
        self.server.response_behavior = [
            {"status": 200, "body": {"accepted": 2, "rejected": []}}
        ]

        summary = dispatch(events, self.url, self.api_key, sleep=lambda x: None, log_path=self.log_path)
        self.assertEqual(summary["accepted"], 2)
        self.assertEqual(summary["rejected"], 0)
        self.assertEqual(summary["failed"], 0)

    def test_partial_rejection(self):
        events = [{"id": 1}, {"id": 2}, {"id": 3}]
        self.server.response_behavior = [
            {"status": 200, "body": {"accepted": 2, "rejected": [{"index": 1, "reason": "bad data"}]}}
        ]

        summary = dispatch(events, self.url, self.api_key, sleep=lambda x: None, log_path=self.log_path)
        self.assertEqual(summary["accepted"], 2)
        self.assertEqual(summary["rejected"], 1)
        self.assertEqual(len(self.server.requests), 1) # only reaches server ONCE

        # Check log
        with open(self.log_path, 'r') as f:
            lines = f.readlines()
            self.assertEqual(len(lines), 1)
            logged = json.loads(lines[0])
            self.assertEqual(logged["event"], {"id": 2})
            self.assertEqual(logged["reason"], "bad data")

    def test_401_stops_no_retry(self):
        events = [{"id": 1}]
        self.server.response_behavior = [{"status": 401, "body": None}]

        with self.assertLogs('dispatcher', level='ERROR') as cm:
            summary = dispatch(events, self.url, self.api_key, sleep=lambda x: None, log_path=self.log_path)

        self.assertEqual(summary["sent"], 0) # never completed sending successfully
        self.assertEqual(len(self.server.requests), 1)

        log_output = "\n".join(cm.output)
        self.assertIn("Unauthorized (401)", log_output)
        self.assertNotIn(self.api_key, log_output)

    def test_503_twice_then_success(self):
        events = [{"id": 1}]
        self.server.response_behavior = [
            {"status": 503, "body": None},
            {"status": 503, "body": None},
            {"status": 200, "body": {"accepted": 1, "rejected": []}}
        ]

        sleep_mock = MagicMock()
        summary = dispatch(events, self.url, self.api_key, sleep=sleep_mock, log_path=self.log_path)

        self.assertEqual(summary["accepted"], 1)
        self.assertEqual(len(self.server.requests), 3)
        self.assertEqual(sleep_mock.call_count, 2)
        sleep_mock.assert_any_call(1)
        sleep_mock.assert_any_call(2)

    def test_500_retried(self):
        events = [{"id": 1}]
        self.server.response_behavior = [
            {"status": 500, "body": None},
            {"status": 200, "body": {"accepted": 1, "rejected": []}}
        ]

        summary = dispatch(events, self.url, self.api_key, sleep=lambda x: None, log_path=self.log_path)
        self.assertEqual(summary["accepted"], 1)
        self.assertEqual(len(self.server.requests), 2)

    def test_413_fails(self):
        events = [{"id": 1}, {"id": 2}]
        self.server.response_behavior = [
            {"status": 413, "body": None}
        ]

        summary = dispatch(events, self.url, self.api_key, sleep=lambda x: None, log_path=self.log_path)

        self.assertEqual(summary["failed"], 2) # batch of 2 failed
        self.assertEqual(len(self.server.requests), 1) # no retry, no split

    def test_422_fails(self):
        events = [{"id": 1}, {"id": 2}]
        self.server.response_behavior = [{"status": 422, "body": None}]

        summary = dispatch(events, self.url, self.api_key, sleep=lambda x: None, log_path=self.log_path)

        self.assertEqual(summary["failed"], 2)
        self.assertEqual(len(self.server.requests), 1) # no retry, no split

    def test_1200_events_split(self):
        events = [{"id": i} for i in range(1200)]
        batches = split_batches(events)

        self.assertEqual(len(batches), 3)
        self.assertEqual(len(batches[0]), 500)
        self.assertEqual(len(batches[1]), 500)
        self.assertEqual(len(batches[2]), 200)

    def test_byte_size_split(self):
        large_str = "x" * 5_000_000
        events = [{"data": large_str}, {"data": large_str}]

        batches = split_batches(events)
        self.assertEqual(len(batches), 2)
        self.assertEqual(len(batches[0]), 1)
        self.assertEqual(len(batches[1]), 1)

    def test_batches_keep_order(self):
        events = [{"id": i} for i in range(1000)]
        batches = split_batches(events)
        self.assertEqual(batches[0][0]["id"], 0)
        self.assertEqual(batches[0][-1]["id"], 499)
        self.assertEqual(batches[1][0]["id"], 500)
        self.assertEqual(batches[1][-1]["id"], 999)

    def test_truncate_event(self):
        event = {
            "process": {
                "args": "a" * 10000,
                "name": "n" * 300,
                "path": "p" * 2000,
                "parent": {
                    "args": "a" * 5000,
                    "path": "p" * 2000
                }
            },
            "alert": {
                "name": "a" * 300
            },
            "host": {
                "hostname": "h" * 300,
                "ip": 12345
            },
            "files": [
                {"path": "f" * 1500}
            ],
            "other": "unchanged"
        }

        truncated = truncate_event(event)

        # Original shouldn't change
        self.assertEqual(len(event["process"]["args"]), 10000)

        # Truncated limits check
        self.assertLessEqual(len(truncated["process"]["args"]), 4096)
        self.assertLessEqual(len(truncated["process"]["path"]), 1024)
        self.assertLessEqual(len(truncated["process"]["parent"]["args"]), 4096)
        self.assertLessEqual(len(truncated["process"]["parent"]["path"]), 1024)
        self.assertLessEqual(len(truncated["process"]["name"]), 256)
        self.assertLessEqual(len(truncated["alert"]["name"]), 256)
        self.assertLessEqual(len(truncated["host"]["hostname"]), 256)
        self.assertLessEqual(len(truncated["files"][0]["path"]), 1024)

        # Specific marker checks for a 10000-char string
        args_truncated = truncated["process"]["args"]
        self.assertTrue(args_truncated.startswith("a" * 100))
        self.assertTrue(args_truncated.endswith("a" * 100))
        self.assertIn("...[truncated", args_truncated)

        # Type conversion
        self.assertEqual(truncated["host"]["ip"], "12345")

        # Unaffected fields
        self.assertEqual(truncated["other"], "unchanged")

    def test_normal_event_unchanged(self):
        event = {
            "process": {"name": "test"},
            "host": {"ip": "1.2.3.4"}
        }
        truncated = truncate_event(event)
        self.assertEqual(event, truncated)

    def test_truncate_text_logic(self):
        # a short string is unchanged
        self.assertEqual(truncate_text("short", 100), "short")

        # long string truncation
        # 10000 char -> 4096 limit
        s = "A" * 100 + "B" * 9800 + "C" * 100
        truncated = truncate_text(s, 4096)
        self.assertLessEqual(len(truncated), 4096)
        self.assertTrue(truncated.startswith("A" * 100))
        self.assertTrue(truncated.endswith("C" * 100))
        self.assertIn("...[truncated", truncated)

    @patch('sys.exit')
    @patch('os.environ.get')
    def test_missing_env_variables_no_values(self, mock_env_get, mock_exit):
        mock_env_get.side_effect = lambda k, default=None: None if k == "INGEST_URL" else "some_key"

        # Running the module directly or simulating cli
        import dispatcher
        import sys

        wazuh_file = os.path.join(self.temp_dir.name, "sample_wazuh.json")
        osquery_file = os.path.join(self.temp_dir.name, "sample_osquery.json")

        test_args = ["dispatcher.py", "--wazuh", wazuh_file, "--osquery", osquery_file]

        # We need to capture stdout
        from io import StringIO
        captured_output = StringIO()
        sys.stdout = captured_output

        try:
            with patch.object(sys, 'argv', test_args):
                # Ensure the json files exist for test
                with open(wazuh_file, "w") as f:
                    f.write("[]")
                with open(osquery_file, "w") as f:
                    f.write("[]")
                # Also mock event_mapper
                with patch('dispatcher.event_mapper') as mock_mapper:
                    mock_mapper.map_events.return_value = {"events": []}
                    dispatcher.main()
        finally:
            sys.stdout = sys.__stdout__

        mock_exit.assert_called_with(1)
        out = captured_output.getvalue()
        self.assertIn("Missing environment variable: INGEST_URL", out)
        self.assertNotIn("some_key", out)

    @patch('sys.exit')
    @patch('os.environ.get')
    def test_dry_run_no_connection(self, mock_env_get, mock_exit):
        import dispatcher
        import sys

        wazuh_file = os.path.join(self.temp_dir.name, "sample_wazuh.json")
        osquery_file = os.path.join(self.temp_dir.name, "sample_osquery.json")

        test_args = ["dispatcher.py", "--wazuh", wazuh_file, "--osquery", osquery_file, "--dry-run"]

        from io import StringIO
        captured_output = StringIO()
        sys.stdout = captured_output

        try:
            with patch.object(sys, 'argv', test_args):
                with open(wazuh_file, "w") as f:
                    f.write("[]")
                with open(osquery_file, "w") as f:
                    f.write("[]")
                with patch('dispatcher.event_mapper') as mock_mapper:
                    mock_mapper.map_events.return_value = {"events": [{"id": 1}], "noise_dropped": 0, "invalid_count": 0}
                    dispatcher.main()
        finally:
            sys.stdout = sys.__stdout__

        self.assertEqual(len(self.server.requests), 0) # No network requests
        out = captured_output.getvalue()
        self.assertIn("number of events: 1", out)
        self.assertIn("number of batches: 1", out)
