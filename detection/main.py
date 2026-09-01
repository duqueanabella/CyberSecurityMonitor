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
    process_names = result.stdout.strip().split("\n")
    return [name.strip() for name in process_names if name.strip()]


def main():
    print("===================================")
    print(" Cybersecurity Monitor")
    print("===================================")

    init_db()

    processes = get_running_processes()
    print(f"Scanned {len(processes)} running processes.")

    found_threat = False

    for process_name in processes:
        if check_process(process_name):
            create_alert(process_name)
            log_event(
                event_type="PROCESS_SCAN",
                process_name=process_name,
                severity="HIGH",
                description=f"Suspicious process detected: {process_name}"
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
