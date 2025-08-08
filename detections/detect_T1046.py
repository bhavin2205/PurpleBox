import subprocess

enum_keywords = [
    # Network discovery
    "Get-NetTCPConnection", "netstat", "Get-NetRoute", "ipconfig",

    # Process/service enumeration
    "Get-Service", "Get-Process", "tasklist",

    # User and group info
    "whoami", "net user", "net localgroup",
    "Get-LocalUser", "Get-LocalGroup", "Get-LocalGroupMember",

    # System info
    "systeminfo", "hostname",

    # Share/session enumeration
    "net view", "net use", "net session"
]

def detect_enum():
    print("[*] Scanning PowerShell logs for enumeration activity...")

    ps_command = """
    Get-WinEvent -LogName 'Microsoft-Windows-PowerShell/Operational' -MaxEvents 50 |
    Where-Object { $_.Id -eq 4104 } |
    Select-Object -ExpandProperty Message
    """

    result = subprocess.run(
        ["powershell", "-Command", ps_command],
        capture_output=True,
        text=True
    )

    output = result.stdout.strip()
    if not output:
        print("[X] No Event ID 4104 logs found.")
        return

    entries = output.split("\n\n")
    found = False

    for entry in entries:
        for keyword in enum_keywords:
            if keyword.lower() in entry.lower():
                print("[MATCH] Enumeration activity detected!")
                print(f"[KEYWORD] {keyword}")
                print(f"[COMMAND]\n{entry}\n")
                found = True
                break

    if not found:
        print("[✔] No enumeration activity found in recent logs.")

if __name__ == "__main__":
    detect_enum()
