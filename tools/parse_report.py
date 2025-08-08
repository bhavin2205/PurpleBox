import os
import sys
from pathlib import Path

# MITRE technique keywords
techniques = {
    "T1059.001": [
        "Invoke-Expression", "IEX", "DownloadString", "FromBase64String",
        "EncodedCommand", "New-Object Net.WebClient", "System.Net.WebClient",
        "Set-ExecutionPolicy", "Add-MpPreference", "Set-MpPreference", "schtasks",
        "Start-Process", "Out-File", "Invoke-Command"
    ],
    "T1595": [
        "Resolve-DnsName", "nslookup", "whois", "Test-Connection", "ping", "tracert",
        "ipconfig", "Get-NetIPConfiguration", "Get-NetRoute", "netstat",
        "Get-NetTCPConnection", "net config", "net use", "net view"
    ],
    "T1046": [
        "Get-Service", "Get-Process", "tasklist", "whoami", "net user", "net localgroup",
        "Get-LocalUser", "Get-LocalGroup", "Get-LocalGroupMember",
        "systeminfo", "hostname", "net session"
    ],
    "T1082": [
        "Get-ComputerInfo"
    ]
}

def identify_technique(line):
    for tid, keywords in techniques.items():
        if any(k.lower() in line.lower() for k in keywords):
            return tid
    return None

def summarize_log(file_path):
    with open(file_path, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    print(f"\n=== Analyzing: {file_path.name} ({len(lines)} lines) ===")
    summary = {}
    suspicious_alerts = []
    found_error = False

    for line in lines:
        if "Errors:" in line or "Traceback" in line:
            found_error = True
        if "[ALERT] Suspicious PowerShell keyword found:" in line:
            suspicious_alerts.append(line.strip())

        tid = identify_technique(line)
        if tid:
            summary[tid] = summary.get(tid, 0) + 1
            print(f"[MATCH] {tid} -> {line.strip()}")

    if not summary:
        print("[✔] No known MITRE techniques matched.")
    if suspicious_alerts:
        print("\n[!] Suspicious PowerShell activity detected:")
        for alert in suspicious_alerts:
            print("   ", alert)
    if found_error:
        print("[!] Errors were logged. Check the full report.")

    return summary

def parse_reports(latest_only=False):
    report_dir = Path("report")
    if not report_dir.exists():
        print("[X] 'report/' folder not found.")
        return

    reports = sorted(report_dir.glob("*.txt"), key=lambda f: f.stat().st_mtime, reverse=True)
    if not reports:
        print("[X] No report files found.")
        return

    print("=== PurpleBox Report Parser ===")
    all_summary = {}

    if latest_only:
        summary = summarize_log(reports[0])
        for tid, count in summary.items():
            all_summary[tid] = all_summary.get(tid, 0) + count
    else:
        for report in reports:
            summary = summarize_log(report)
            for tid, count in summary.items():
                all_summary[tid] = all_summary.get(tid, 0) + count

    print("\n=== Detection Summary ===")
    if all_summary:
        for tid, count in all_summary.items():
            print(f"{tid}: {count} match(es)")
    else:
        print("[✔] No detections across parsed reports.")

if __name__ == "__main__":
    latest_flag = "--latest" in sys.argv
    parse_reports(latest_only=latest_flag)
