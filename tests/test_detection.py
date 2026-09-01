import sys
import os

sys.path.append(os.path.join(os.path.dirname(__file__), "..", "detection"))
from rules import check_process, check_connections # type: ignore


def test_known_suspicious_name():
    is_suspicious, reason = check_process("malware.exe", "C:\\Windows\\malware.exe")
    assert is_suspicious == True
    assert reason == "known suspicious name"


def test_normal_process_is_clean():
    is_suspicious, reason = check_process("chrome.exe", "C:\\Program Files\\Google\\Chrome\\chrome.exe")
    assert is_suspicious == False
    assert reason is None


def test_suspicious_location():
    is_suspicious, reason = check_process("notepad.exe", "C:\\Users\\parat\\Downloads\\notepad.exe")
    assert is_suspicious == True
    assert "suspicious location" in reason


def test_loopback_connection_is_ignored():
    connections = [("1111", "127.0.0.1", "1337")]
    findings = check_connections(connections)
    assert findings == []


def test_external_suspicious_port_is_flagged():
    connections = [("2222", "45.33.32.156", "4444")]
    findings = check_connections(connections)
    assert len(findings) == 1
    pid, reason = findings[0]
    assert pid == "2222"
    assert "suspicious port" in reason