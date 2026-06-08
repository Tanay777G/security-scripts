"""
File Integrity Monitor — SOC Home Lab Tool
Author: Tanay Shirsat
Purpose: Monitor a directory for unauthorised file changes using SHA-256.
         Alerts on files added, modified, or deleted.
Security Use Case: Detect attacker persistence (web shells, config tampering).
MITRE ATT&CK: T1565 - Data Manipulation | T1036 - Masquerading
"""

import hashlib, os, json, sys
from datetime import datetime

BASELINE_FILE = "fim_baseline.json"
ALERT_LOG     = "fim_alerts.log"


def hash_file(filepath):
    sha256 = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    except (PermissionError, FileNotFoundError):
        return None


def create_baseline(directory):
    baseline = {}
    for root, _, files in os.walk(directory):
        for fname in files:
            fp = os.path.join(root, fname)
            h = hash_file(fp)
            if h:
                baseline[fp] = {"hash": h, "baseline_time": datetime.now().isoformat()}
    with open(BASELINE_FILE, "w") as f:
        json.dump(baseline, f, indent=2)
    print(f"[FIM] Baseline created — {len(baseline)} files recorded.")
    return baseline


def scan_and_compare(directory):
    if not os.path.exists(BASELINE_FILE):
        print("[ERROR] No baseline found. Run with --baseline first.")
        return
    with open(BASELINE_FILE) as f:
        baseline = json.load(f)

    current = {}
    for root, _, files in os.walk(directory):
        for fname in files:
            fp = os.path.join(root, fname)
            h = hash_file(fp)
            if h:
                current[fp] = h

    alerts = 0
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    for fp, info in baseline.items():
        if fp not in current:
            msg = f"[{timestamp}] [DELETED]  {fp}"
            print(f"  [ALERT] FILE DELETED: {fp}")
            open(ALERT_LOG, "a").write(msg + "\n")
            alerts += 1
        elif current[fp] != info["hash"]:
            msg = f"[{timestamp}] [MODIFIED] {fp}"
            print(f"  [ALERT] FILE MODIFIED: {fp}")
            open(ALERT_LOG, "a").write(msg + "\n")
            alerts += 1

    for fp in current:
        if fp not in baseline:
            msg = f"[{timestamp}] [NEW FILE] {fp}"
            print(f"  [ALERT] NEW FILE: {fp}")
            open(ALERT_LOG, "a").write(msg + "\n")
            alerts += 1

    if alerts == 0:
        print(f"  [FIM] No changes — all {len(baseline)} files intact.")
    else:
        print(f"\n  [FIM] {alerts} alert(s) — see {ALERT_LOG}")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage:\n  python file_integrity_monitor.py --baseline 
\n  python file_integrity_monitor.py --scan 
")
        sys.exit(0)
    if sys.argv[1] == "--baseline":
        create_baseline(sys.argv[2])
    elif sys.argv[1] == "--scan":
        scan_and_compare(sys.argv[2])
