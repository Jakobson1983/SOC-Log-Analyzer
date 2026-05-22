#!/bin/bash

# SOC Log Analyzer
# Description:
# This tool parses Windows/Sysmon JSON logs and generates a basic SOC-style report.
# It helps identify Event IDs, LSASS access, PowerShell activity, LOLBAS usage,
# and basic network connections.
#
# Author: Jakub Zytlinski
# Version: 0.2

LOG_FILE="$1"
REPORT_DIR="reports"
REPORT_FILE="$REPORT_DIR/sysmon_report_$(date +%Y-%m-%d_%H-%M-%S).txt"

show_help() {
    echo "SOC Log Analyzer"
    echo
    echo "Usage:"
    echo "  ./soc_log_analyzer.sh <logfile>"
    echo
    echo "Example:"
    echo "  ./soc_log_analyzer.sh samples/win-training.log"
    echo
    echo "Requirements:"
    echo "  jq"
}

if [[ "$1" == "--help" || "$1" == "-h" ]]; then
    show_help
    exit 0
fi

if ! command -v jq >/dev/null 2>&1; then
    echo "[ERROR] jq is not installed."
    echo "Install it with: sudo apt install jq"
    exit 1
fi

if [ -z "$LOG_FILE" ]; then
    echo "[ERROR] No log file provided."
    echo
    show_help
    exit 1
fi

if [ ! -f "$LOG_FILE" ]; then
    echo "[ERROR] File not found: $LOG_FILE"
    exit 1
fi

mkdir -p "$REPORT_DIR"

{
echo "===================================="
echo "          SOC LOG ANALYZER"
echo "===================================="
echo "Report date: $(date)"
echo "Analyzed file: $LOG_FILE"
echo

echo "[1] Top Event IDs"
jq -r '.EventID // empty' "$LOG_FILE" 2>/dev/null \
| sort \
| uniq -c \
| sort -nr \
| head -15
echo

echo "[2] Event ID quick reference"
echo "1    - Process Creation"
echo "3    - Network Connection"
echo "7    - Image Loaded"
echo "10   - Process Access"
echo "11   - File Created"
echo "12   - Registry Object Created/Deleted"
echo "13   - Registry Value Set"
echo "22   - DNS Query"
echo "4624 - Successful Logon"
echo "4625 - Failed Logon"
echo "4688 - Process Creation"
echo "4698 - Scheduled Task Created"
echo

echo "[3] Top Source Images"
jq -r '.SourceImage // empty' "$LOG_FILE" 2>/dev/null \
| sort \
| uniq -c \
| sort -nr \
| head -10
echo

echo "[4] Top Target Images"
jq -r '.TargetImage // empty' "$LOG_FILE" 2>/dev/null \
| sort \
| uniq -c \
| sort -nr \
| head -10
echo

echo "[5] Process Access Events - EventID 10"
echo "SOC note: EventID 10 may be important when a process accesses lsass.exe."
jq -r '
select(.EventID == 10)
| (.SourceImage // "unknown_source") + " -> " + (.TargetImage // "unknown_target")
' "$LOG_FILE" 2>/dev/null \
| head -25
echo

echo "[6] LSASS Access Check"
echo "SOC note: Access to lsass.exe can indicate credential dumping attempts."
jq -r '
select(.EventID == 10)
| select((.TargetImage // "" | ascii_downcase) | contains("lsass.exe"))
| "ALERT: " + (.SourceImage // "unknown_source") + " accessed " + (.TargetImage // "unknown_target")
' "$LOG_FILE" 2>/dev/null \
| head -25
echo

echo "[7] PowerShell Activity"
echo "SOC note: PowerShell is legitimate but often abused by attackers."
jq -r '
select(
  ((.Image // "") | ascii_downcase | contains("powershell"))
  or
  ((.SourceImage // "") | ascii_downcase | contains("powershell"))
  or
  ((.CommandLine // "") | ascii_downcase | contains("powershell"))
)
| (.Image // .SourceImage // "unknown_image") + " " + (.CommandLine // "")
' "$LOG_FILE" 2>/dev/null \
| head -25
echo

echo "[8] LOLBAS Activity"
echo "SOC note: LOLBAS are legitimate Windows binaries abused by attackers."
jq -r '
select(
  ((.Image // "") | ascii_downcase | test("certutil|bitsadmin|rundll32|regsvr32|wmic|mshta"))
  or
  ((.SourceImage // "") | ascii_downcase | test("certutil|bitsadmin|rundll32|regsvr32|wmic|mshta"))
  or
  ((.CommandLine // "") | ascii_downcase | test("certutil|bitsadmin|rundll32|regsvr32|wmic|mshta"))
)
| "SUSPICIOUS: " + (.Image // .SourceImage // "unknown_image") + " " + (.CommandLine // "")
' "$LOG_FILE" 2>/dev/null \
| head -30
echo

echo "[9] Network Connections - EventID 3"
jq -r '
select(.EventID == 3)
| (.Image // "unknown_image") + " -> " + (.DestinationIp // "unknown_ip") + ":" + (.DestinationPort // "unknown_port" | tostring)
' "$LOG_FILE" 2>/dev/null \
| head -25
echo

echo "[10] Basic Summary"
echo "Total events:"
wc -l "$LOG_FILE" | awk "{print \$1}"
echo
echo "Report saved to: $REPORT_FILE"

} | tee "$REPORT_FILE"
