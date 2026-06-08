"""
Windows Event Log Parser — SOC Home Lab Tool
Author: Tanay Shirsat
Purpose: Parse exported Windows Security logs and flag suspicious Event IDs.
Security Use Case: Automate first-pass triage during incident response.
MITRE Coverage:
  T1110 - Brute Force          (Event ID 4625)
  T1059 - Scripting Interpreter(Event ID 4688)
  T1550 - Alternate Auth       (Event ID 4648)
  T1068 - Privilege Escalation (Event ID 4672)
"""

import re, sys
from datetime import datetime
from collections import defaultdict

SUSPICIOUS = {
    "4625": ("FAILED LOGON",         "Credential Access — possible brute force"),
    "4688": ("PROCESS CREATION",     "Execution — watch for LOLBin abuse"),
    "4648": ("EXPLICIT CREDENTIALS", "Lateral Movement — pass-the-hash indicator"),
    "4672": ("SPECIAL PRIVILEGES",   "Privilege Escalation — admin rights assigned"),
    "4698": ("SCHEDULED TASK",       "Persistence — possible backdoor"),
    "4720": ("ACCOUNT CREATED",      "Persistence — new user account"),
    "1102": ("AUDIT LOG CLEARED",    "Defence Evasion — attacker covering tracks"),
}


def parse_file(filepath):
    counts = defaultdict(int)
    samples = defaultdict(list)
    total = 0
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            for i, line in enumerate(f, 1):
                total += 1
                m = re.search(r'\b(4625|4688|4648|4672|4698|4720|1102)\b', line)
                if m:
                    eid = m.group(1)
                    counts[eid] += 1
                    if len(samples[eid]) < 2:
                        samples[eid].append(f"  Line {i}: {line.strip()[:100]}")
    except FileNotFoundError:
        print(f"[ERROR] File not found: {filepath}")
        sys.exit(1)
    return total, counts, samples


def print_report(filepath, total, counts, samples):
    print("\n" + "="*65)
    print("  SOC TRIAGE REPORT — WINDOWS EVENT LOG")
    print("="*65)
    print(f"  File     : {filepath}")
    print(f"  Lines    : {total:,}")
    print(f"  Analysed : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("-"*65)
    if not counts:
        print("  No suspicious Event IDs detected.")
    else:
        print(f"  {'Event ID':<12} {'Count':<8} {'Type':<26} ATT&CK Context")
        print(f"  {'-'*11} {'-'*7} {'-'*25} {'-'*25}")
        for eid, count in sorted(counts.items(), key=lambda x: -x[1]):
            label, context = SUSPICIOUS[eid]
            print(f"  {eid:<12} {count:<8} {label:<26} {context}")
    print("\n  ANALYST NOTES:")
    if counts.get("4625", 0) > 5:
        print("  [!] High failed logins — investigate for brute force source IP")
    if "1102" in counts:
        print("  [!!] AUDIT LOG CLEARED — critical. Possible defence evasion.")
    if "4698" in counts:
        print("  [!] Scheduled task created — check for attacker persistence")
    print("="*65 + "\n")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python log_parser.py ")
        sys.exit(0)
    total, counts, samples = parse_file(sys.argv[1])
    print_report(sys.argv[1], total, counts, samples)
