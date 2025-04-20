import subprocess
import sys
import datetime
import os
import json

CONFIG_PATH = "config.json"

def log_output(text):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = f"report/report_{timestamp}.txt"
    with open(filename, 'a', encoding='utf-8') as f:
        f.write(text + "\n")
    print(text)

def run_attack(script_path, label):
    log_output(f"\n[*] Running PowerShell Simulation ({label})...")
    result = subprocess.run(
        ["powershell", "-ExecutionPolicy", "Bypass", "-File", script_path],
        capture_output=True,
        text=True
    )
    log_output(result.stdout)
    if result.stderr:
        log_output("[!] Errors:\n" + result.stderr)

def run_detection(script_path, label):
    log_output(f"\n[*] Running Detection Script ({label})...")
    result = subprocess.run(
        [sys.executable, script_path],
        capture_output=True,
        text=True
    )
    log_output(result.stdout)
    if result.stderr:
        log_output("[!] Errors:\n" + result.stderr)

def load_config():
    if not os.path.exists(CONFIG_PATH):
        print("[!] Config file not found.")
        return None
    with open(CONFIG_PATH, 'r') as f:
        return json.load(f)

def run_from_config():
    config = load_config()
    if not config:
        return

    for tech in config.get("techniques", []):
        if tech == "T1059.001":
            run_attack("attacks/T1059_powershell.ps1", tech)
            run_detection("detections/detect_T1059.py", tech)
        elif tech == "T1082":
            run_attack("attacks/T1082_discovery.ps1", tech)
            run_detection("detections/detect_T1082.py", tech)
        else:
            log_output(f"[!] Unknown technique: {tech}")

def main():
    while True:
        print("\n=== PurpleBox Menu ===")
        print("1. Simulate PowerShell Attack (T1059.001)")
        print("2. Run Detection for PowerShell (T1059.001)")
        print("3. Run Both (T1059.001)")
        print("4. Simulate T1082 - System Discovery")
        print("5. Detect T1082")
        print("6. Run Config Automation")
        print("7. Exit")

        choice = input("Select an option: ")

        if choice == '1':
            run_attack("attacks/T1059_powershell.ps1", "T1059.001")
        elif choice == '2':
            run_detection("detections/detect_T1059.py", "T1059.001")
        elif choice == '3':
            run_attack("attacks/T1059_powershell.ps1", "T1059.001")
            run_detection("detections/detect_T1059.py", "T1059.001")
        elif choice == '4':
            run_attack("attacks/T1082_discovery.ps1", "T1082")
        elif choice == '5':
            run_detection("detections/detect_T1082.py", "T1082")
        elif choice == '6':
            run_from_config()
        elif choice == '7':
            print("Exiting PurpleBox.")
            break
        else:
            print("Invalid choice. Try again.")

if __name__ == "__main__":
    main()
