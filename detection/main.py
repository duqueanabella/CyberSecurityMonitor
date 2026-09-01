import subprocess
import sys
import os
from rules import check_process, check_connections
from alerts import create_alert

sys.path.append(os.path.join(os.path.dirname(__file__), "..", "database"))
from database import init_db, log_event


def collect_data():
    result = subprocess.run(
        ["powershell", "-File", "collector/get_system_info.ps1"],
        capture_output=True,
        text=True
    )
    lines = result.stdout.strip().split("\n")

    processes = []
    connections = []
    in_network_section = False

    for line in lines:
        line = line.strip()
        if not line:
            continue
        if line == "---NETWORK---":
            in_network_section = True
            continue

        parts = line.split("|")
        if in_network_section:
            if len(parts) == 3:
                pid, remote_ip, remote_port = parts
                connections.append((pid.strip(), remote_ip.strip(), remote_port.strip()))
        else:
            if len(parts) ==2:
                name, path = parts
                processes.append((name.strip(), path.strip()))

    return processes, connections



def main():
    print("===================================")
    print(" Cybersecurity Monitor")
    print("===================================")

    init_db()


    processes, connections = collect_data()
    print(f"Scanned {len(processes)} running processes.")
    print(f"Scanned {len(connections)} active network connections.")

    found_threat = False

    for process_name, process_path in processes:
        is_suspicious, reason = check_process(process_name, process_path)
        if is_suspicious:
            create_alert(process_name)
            log_event(
                event_type="PROCESS_SCAN",
                process_name=process_name,
                severity="HIGH",
                description=f"Suspicious process detected: {process_name} ({reason}) at {process_path}"
            )
            found_threat = True

    network_findings = check_connections(connections)
    for pid, remote_ip, reason in network_findings:
        create_alert(f"PID {pid}")
        log_event(
            event_type="NETWORK_SCAN",
            process_name=f"PID {pid}",
            severity="HIGH",
            description=f"Suspicious network activity for PID {pid}: {reason}"
        )
        found_threat = True

    if not found_threat:
        print("No suspicious activity detected.")
        log_event(
            event_type="PROCESS_SCAN",
            process_name=None,
            severity="INFO",
            description=f"Scan completed. {len(processes)} processes checked, {len(connections)} network connections checked, none flagged."
        )

if __name__ == "__main__":
    main()

