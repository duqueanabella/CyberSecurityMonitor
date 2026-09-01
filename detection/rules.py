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
