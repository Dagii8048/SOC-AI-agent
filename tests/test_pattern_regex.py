import re

def test_p003_regex():
    assert re.match("(?i).*\\\\config\\\\SAM$", "C:\\Windows\\System32\\config\\SAM")
    assert re.match("(?i).*NTDS\\.dit$", "C:\\Windows\\NTDS\\ntds.dit")

    # negatives
    assert not re.match("(?i).*\\\\config\\\\SAM$", "C:\\Windows\\System32\\config\\SAMPLE.txt")

def test_p008_regex():
    assert re.match("(?i).*\\\\CurrentVersion\\\\Run\\\\.*", "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\malware")
    assert re.match("(?i).*\\\\Startup\\\\.*", "C:\\Users\\bob\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\malware.exe")

    # negatives
    assert not re.match("(?i).*\\\\CurrentVersion\\\\Run\\\\.*", "C:\\Users\\bob\\Downloads\\Runtime\\malware.exe")
