# PurpleBox – MITRE ATT&CK Simulation & Detection Toolkit

PurpleBox is a lightweight toolkit to simulate and detect MITRE ATT&CK techniques like T1059.001 (PowerShell) and T1082 (System Info Discovery). Built as a personal security portfolio project.

## 💻 Features
- Simulate MITRE ATT&CK techniques using PowerShell
- Detect activity using Windows Event Logs (4104)
- Generate timestamped log reports
- Parse results with summary script
- Config-driven execution support

## 📁 Folder Structure
- `attacks/` – PowerShell scripts
- `detections/` – Python detection scripts
- `report/` – Logged outputs from runs
- `tools/parse_report.py` – Log summarizer
- `config.json` – Optional automation config
- `purplebox.py` – Main CLI tool

## 🚀 How to Run
```bash
python purplebox.py