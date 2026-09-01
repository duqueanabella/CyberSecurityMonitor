import subprocess
import sys
import os
from rules import check_process
from alerts import create_alert

sys.path.append(os.path.join(os.path.dirname(__file__), "..", "database"))
from database import init_db, log_event


def get_running_processes():
    result = subprocess.run(
        ["powershell", "-File", "collector/get_system_info.ps1"],
        capture_output=True,
        text=True
    )
    lines = result.stdout.strip().split("\n")
    processes = []
    for line in lines:
        line = line.strip()
        if not line or "|" not in line:
            continue
        name, path = line.split("|",1)
        processes.append((name.strip(),path.strip()))
    return processes


def main():
    print("===================================")
    print(" Cybersecurity Monitor")
    print("===================================")

    init_db()


    processes = get_running_processes()
    print(f"Scanned {len(processes)} running processes.")

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

    if not found_threat:
        print("No suspicious activity detected.")
        log_event(
            event_type="PROCESS_SCAN",
            process_name=None,
            severity="INFO",
            description=f"Scan completed. {len(processes)} processes checked, none flagged."
        )

if __name__ == "__main__":
    main()
    