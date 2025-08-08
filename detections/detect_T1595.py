import subprocess

# Expanded list of reconnaissance-related PowerShell commands
recon_keywords = [
    # DNS / Domain Recon
    "Resolve-DnsName", "nslookup", "whois",

    # Network Probing / IP discovery
    "Test-Connection", "ping", "tracert", "ipconfig",
    "Get-NetIPConfiguration", "Get-NetRoute",

    # Host Information
    "hostname", "systeminfo", "Get-ComputerInfo",

    # HTTP Recon / Command & Control Check
    "Invoke-WebRequest", "Invoke-RestMethod", "curl", "wget",

    # General Fingerprinting & Discovery
    "netstat", "Get-Process", "Get-Service", "Get-WmiObject",
    "Get-NetTCPConnection", "net config", "net use", "net view"
]

def detect_recon():
    print("[*] Scanning PowerShell logs for reconnaissance activity...")

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
        for keyword in recon_keywords:
            if keyword.lower() in entry.lower():
                print("[MATCH] Recon activity detected!")
                print(f"[KEYWORD] {keyword}")
                print(f"[COMMAND]\n{entry}\n")
                found = True
                break

    if not found:
        print("[✔] No recon activity found in recent logs.")

if __name__ == "__main__":
    detect_recon()
