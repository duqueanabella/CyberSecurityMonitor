from operator import is_


def check_process(process_name, process_path=""):
    suspicious_names = [
        "malware.exe",
        "virus.exe",
        "ransomware.exe"
    ]

    suspicious_locations = [
        "\\temp\\",
        "\\downloads\\",
        "\\appdata\\local\\temp\\"
    ]

    name_lower = process_name.lower()
    path_lower = process_path.lower()

    if name_lower in suspicious_names:
        return True, "known suspicious name"

    for location in suspicious_locations:
        if location in path_lower:
            return True, f"running from suspicious location ({location.strip(chr(92))})"

    return False, None


def check_connections(connections):
    suspicious_ports = ["4444", "1337", "31337", "5555", "6666", "6667"]

    process_connection_counts = {}
    process_reasons = {}

    for pid, remote_ip, remote_port in connections:
        process_connection_counts[pid] = process_connection_counts.get(pid, 0) + 1

        is_loopback = remote_ip.startswith("127.") or remote_ip == "::1"

        if remote_port in suspicious_ports and not is_loopback:
            reason = f"connection to known suspicious port {remote_port} ({remote_ip}:{remote_port})"
            process_reasons.setdefault(pid, []).append(reason)

    for pid, count in process_connection_counts.items():
        if count > 20:
            reason = f"unusually high connection count ({count} connections)"
            process_reasons.setdefault(pid, []).append(reason)

    findings = []
    for pid, reasons in process_reasons.items():
        combined_reason = "; ".join(reasons)
        findings.append((pid, combined_reason))

    return findings
