# SOC Log Analyzer

Basic Bash-based SOC log analyzer for Windows/Sysmon JSON logs.

## About This Project

This is a personal SOC learning project created to practice:

- Bash scripting
- Windows/Sysmon log analysis
- SOC investigation concepts
- jq JSON parsing
- Linux command-line workflows

The goal of this project is educational and focused on improving practical SOC analyst skills.

---

## Features

- Event ID statistics
- Event ID quick reference
- LSASS access detection
- PowerShell activity detection
- LOLBAS detection
- Network connection analysis
- SOC-style report generation
- JSON log parsing with jq

---

## Skills Practiced

- Bash scripting
- jq
- Sysmon analysis
- Event ID investigation
- PowerShell detection
- LOLBAS detection
- Linux command-line workflows
- Report generation
- Git/GitHub workflow

---

## Requirements

- Bash
- jq

Install jq:

```bash
sudo apt install jq
```

---

## Usage

Make the script executable:

```bash
chmod +x soc_log_analyzer.sh
```

Run the analyzer:

```bash
./soc_log_analyzer.sh sample.log
```

Display help menu:

```bash
./soc_log_analyzer.sh --help
```

---

## Example Detections

The tool can help identify:

- EventID 10 - Process Access
- LSASS access attempts
- Suspicious PowerShell activity
- LOLBAS activity
- Basic network connection events
- Suspicious Windows binaries usage

---

## Example Output

```text
[6] LSASS Access Check

ALERT: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe accessed C:\Windows\System32\lsass.exe
```

---

## Project Structure

```text
SOC-Log-Analyzer/
├── soc_log_analyzer.sh
├── README.md
├── reports/
├── samples/
└── screenshots/
```

---

## Notes

This project is intended for educational and SOC training purposes only.

Sample logs should not contain sensitive or private information.

---

## Future Improvements

- MITRE ATT&CK mapping
- CSV export
- HTML report generation
- IOC extraction
- Sigma rule support
- Threat scoring
- Linux auth.log support
- Better detection logic

---

## Author

Jakub Zytlinski
