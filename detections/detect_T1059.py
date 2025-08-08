import subprocess

suspicious_keywords = [
    "Invoke-WebRequest", "Invoke-Expression", "IEX", "DownloadString", "FromBase64String",
    "EncodedCommand", "New-Object Net.WebClient", "System.Net.WebClient",
    "Set-ExecutionPolicy", "Add-MpPreference", "Set-MpPreference", "schtasks",
    "Start-Process", "Out-File", "Invoke-Command", "Get-WmiObject", "Get-ChildItem",
    "net user", "net localgroup", "whoami", "Get-LocalUser", "Get-LocalGroup",
    "Add-LocalGroupMember", "Get-Content", "Get-Process", "Get-Service",
    "Get-ScheduledTask", "Get-EventLog", "Get-ComputerInfo"
]

def detect_from_getwinevent():
    print("[*] Scanning PowerShell logs via Get-WinEvent...")

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
        print("[X] No 4104 events returned by Get-WinEvent.")
        return

    entries = output.split("\n\n")  # split individual entries
    found = False

    for entry in entries:
        for keyword in suspicious_keywords:
            if keyword.lower() in entry.lower():
                print("[MATCH] Suspicious command detected!")
                print(f"[KEYWORD] {keyword}")
                print(f"[COMMAND]\n{entry}\n")
                found = True
                break

    if not found:
        print("[✔] No suspicious PowerShell commands detected in recent logs.")

if __name__ == "__main__":
    detect_from_getwinevent()
