from pathlib import Path

def summarize_log(file_path):
    with open(file_path, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    print("\n=== Summary Report ===")
    print(f"Analyzing: {file_path.name} ({len(lines)} lines)")

    found_t1059 = any("T1059" in line or "Script Block Execution Detected" in line for line in lines)
    found_t1082 = any("Get-ComputerInfo" in line or "T1082" in line for line in lines)
    found_error = any("Errors:" in line or "Traceback" in line for line in lines)

    if found_t1059:
        print("[OK] T1059.001 detected (PowerShell Script Execution).")
    if found_t1082:
        print("[OK] T1082 detected (System Information Discovery).")
    if not found_t1059 and not found_t1082:
        print("[X] No known MITRE technique matched.")

    if found_error:
        print("[!] Errors were logged. Check the full report.")

if __name__ == "__main__":
    report_dir = Path("report")
    reports = sorted(report_dir.glob("*.txt"), key=lambda f: f.stat().st_size, reverse=True)

    if not reports:
        print("No report files found in the 'report/' folder.")
    else:
        summarize_log(reports[0])
