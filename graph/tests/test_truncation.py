import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import pytest
from pydantic import ValidationError
from ingest_router import EventSchema, truncate_head_tail


def event(**extra):
    e = {"alert": {"id": "A1", "timestamp": 1234567890000}}
    e.update(extra)
    return e


def test_short_text_unchanged():
    assert truncate_head_tail("abc", 10) == "abc"
    assert truncate_head_tail("x" * 4096, 4096) == "x" * 4096  # exactly at the limit


def test_non_string_unchanged():
    assert truncate_head_tail(123, 5) == 123


def test_long_args_are_shortened_not_rejected():
    args = "HEAD_FLAGS " + "A" * 5000 + " PAYLOAD_AT_THE_END"
    ev = EventSchema(**event(process={"pid": 1, "name": "powershell.exe", "args": args}))
    out = ev.process.args
    assert len(out) <= 4096
    assert out.startswith("HEAD_FLAGS ")
    assert out.endswith("PAYLOAD_AT_THE_END")
    assert "[truncated" in out


def test_marker_reports_removed_count():
    original = "z" * 5000
    out = truncate_head_tail(original, 4096)
    removed = int(out.split("[truncated ")[1].split(" chars]")[0])
    kept = len(out) - len(f" ...[truncated {removed} chars]... ")
    assert len(out) <= 4096
    assert kept + removed == len(original)


def test_result_never_exceeds_limit():
    for limit in (256, 1024, 4096):
        for n in (limit + 1, limit + 2, limit * 3, 10_000_000):
            assert len(truncate_head_tail("q" * n, limit)) <= limit


def test_other_evidence_fields_are_shortened():
    ev = EventSchema(**event(
        process={"pid": 1, "name": "n" * 300, "path": "p" * 2000, "hash": "h" * 400,
                 "parent": {"pid": 2, "args": "a" * 5000},
                 "children": [{"pid": 3, "args": "c" * 5000}]},
        files=[{"path": "f" * 2000, "op": "write"}],
        network=[{"dest_ip": "1.2.3.4", "dest_port": 80, "protocol": "T" * 300}],
    ))
    assert len(ev.process.name) <= 256
    assert len(ev.process.path) <= 1024
    assert len(ev.process.hash) <= 256
    assert len(ev.process.parent.args) <= 4096
    assert len(ev.process.children[0].args) <= 4096
    assert len(ev.files[0].path) <= 1024
    assert len(ev.network[0].protocol) <= 256


def test_identity_fields_are_still_rejected_when_too_long():
    bad_events = [
        {"alert": {"id": "x" * 300, "timestamp": 1234567890000}},
        event(host={"hostname": "h" * 300}),
        event(user={"username": "u" * 300}),
        event(network=[{"dest_ip": "1" * 300, "dest_port": 80, "protocol": "TCP"}]),
        event(logged_in_hosts=["h" * 300]),
        event(scanned_hosts=["h" * 300]),
    ]
    for bad in bad_events:
        with pytest.raises(ValidationError):
            EventSchema(**bad)


def test_wrong_type_still_rejected():
    with pytest.raises(ValidationError):
        EventSchema(**event(process={"pid": 1, "args": 12345}))
