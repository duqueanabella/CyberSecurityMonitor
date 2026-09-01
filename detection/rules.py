def check_process(process_name):
    suspicious_processes = [
        "malware.exe",
        "virus.exe",
        "ransomware.exe"

    ]

    if process_name.lower() in suspicious_processes:
        return True

    return False
