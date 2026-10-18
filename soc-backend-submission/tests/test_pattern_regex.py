import pytest
import sys
import os
import re
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pattern_library import PATTERNS

def extract_regexes(cypher_str, target):
    regexes = []
    lines = cypher_str.split('\n')
    for line in lines:
        if target in line and "=~" in line:
            parts = line.split("=~ '")
            for part in parts[1:]:
                raw_regex = part.split("'")[0]

                # Cypher unescape:
                # cypher string r"(?i).*\\\\config\\\\SAM$" -> Java regex "(?i).*\\config\\SAM$"
                # Python re expects literal backslashes to be escaped.
                # In Python `re.match(r"(?i).*\\config\\SAM$", string)` works because `r"..."` handles it.
                # So if Cypher passes `\\` to java to match a single backslash, Python needs `\\` as well!
                # Since raw_regex is already `\\\\`, we just replace `\\\\` with `\\`.
                # For `ntds\\.dit`, we want Python re to see `\.` (literal dot).
                # `raw_regex` has `\\\\.dit`. Replacing `\\\\` with `\\` gives `\\.dit`.
                # `\\.dit` in python `re` means backslash followed by any char! That's `re.error: bad escape \c` if it thinks it's a python escape.
                # Actually `\c` in python regex is bad escape. It's coming from `\\config` -> `\config`.
                # Ah! We are doing `replace(r'\\\\', r'\\')`, which turns `\\\\config` into `\\config`.
                # But wait, `re.match` is throwing `bad escape \c` because `\\config` is seen by `re` as a string, not a raw string!
                # Wait, if we pass a string `\\config` to `re.compile`, it sees two backslashes. Two backslashes mean "escape the next thing".
                # Oh, string `\\config` has ONE backslash! Because we didn't use raw string for the replace replacement!

                # Let's be explicit:
                # raw_regex is a python string containing four backslashes.
                unescaped_regex = raw_regex.replace('\\\\', '\\')
                regexes.append(unescaped_regex)
    return regexes

def test_p003_regex():
    p003 = next((p for p in PATTERNS if p["id"] == "P-003"), None)
    assert p003 is not None, "P-003 not found"

    regexes = extract_regexes(p003["cypher"], "f.path")
    assert len(regexes) == 2, "Expected 2 regex conditions in P-003"

    sam_regex, ntds_regex = regexes

    assert re.match(sam_regex, r"C:\Windows\System32\config\SAM")
    assert not re.match(sam_regex, r"C:\Windows\System32\config\SAMPLE.txt")

    assert re.match(ntds_regex, r"C:\Windows\NTDS\ntds.dit")

def test_p008_regex():
    p008 = next((p for p in PATTERNS if p["id"] == "P-008"), None)
    assert p008 is not None, "P-008 not found"

    regexes = extract_regexes(p008["cypher"], "f.path")
    assert len(regexes) == 2, "Expected 2 regex conditions in P-008"

    run_regex, startup_regex = regexes

    assert re.match(run_regex, r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run\x")
    assert not re.match(run_regex, r"C:\Downloads\Runtime\x.exe")
    assert re.match(startup_regex, r"C:\Users\bob\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\m.exe")
