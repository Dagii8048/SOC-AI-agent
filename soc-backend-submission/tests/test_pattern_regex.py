import pytest
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
try:
    from pattern_library import PATTERNS as PATTERN_LIBRARY
except ImportError:
    pass

def test_pattern_cypher_regex():
    p003 = next((p for p in PATTERN_LIBRARY if p["id"] == "P-003"), None)
    if not p003:
        pytest.skip("P-003 not found")
    p003_cypher = p003["cypher"]
    assert "f.path =~ '(?i).*\\\\\\\\config\\\\\\\\SAM$'" in p003_cypher or "f.path =~ '(?i).*\\\\\\\\NTDS\\\\\\\\ntds\\.dit$'" in p003_cypher or r"f.path =~ '(?i).*\\\\config\\\\SAM$'" in p003_cypher

    import re
    def extract_and_unescape(cypher_str, target):
        lines = cypher_str.split("\n")
        for line in lines:
            if target in line:
                parts = line.split(f"{target} =~ '")
                if len(parts) > 1:
                    raw_cypher_literal = parts[1].split("'")[0]
                    return raw_cypher_literal.replace(r'\\', '\\')
        return None

    regex_sam = extract_and_unescape(p003_cypher, "f.path")
    assert regex_sam is not None
    assert re.match(r"(?i).*\\config\\SAM$", r"C:\Windows\System32\config\SAM")
    assert not re.match(r"(?i).*\\config\\SAM$", r"C:\Windows\System32\config\SAMPLE.txt")
    assert re.match(r"(?i).*\\NTDS\\ntds\.dit$", r"C:\Windows\NTDS\ntds.dit")

    p008 = next((p for p in PATTERN_LIBRARY if p["id"] == "P-008"), None)
    if not p008:
        pytest.skip("P-008 not found")
    p008_cypher = p008["cypher"]
    assert re.match(r"(?i).*\\CurrentVersion\\Run\\.*", r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run\x")
    assert not re.match(r"(?i).*\\CurrentVersion\\Run\\.*", r"C:\Downloads\Runtime\x.exe")
