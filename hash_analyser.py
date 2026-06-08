"""
Hash Analyser — SOC Home Lab Tool
Author: Tanay Shirsat
Purpose: Compare MD5, SHA-256, SHA-512 hashes of a file
         for malware identification and integrity verification.
Security Use Case: During IR, compare suspect file hash against
                   VirusTotal or MalwareBazaar databases.
"""

import hashlib
import os
import sys
from datetime import datetime


def calculate_hashes(filepath):
    if not os.path.exists(filepath):
        print(f"[ERROR] File not found: {filepath}")
        sys.exit(1)

    algorithms = {
        "MD5":     hashlib.md5(),
        "SHA-256": hashlib.sha256(),
        "SHA-512": hashlib.sha512()
    }

    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            for algo in algorithms.values():
                algo.update(chunk)

    return {name: algo.hexdigest() for name, algo in algorithms.items()}


def print_report(filepath, hashes):
    print("\n" + "="*60)
    print("  HASH ANALYSIS REPORT")
    print("="*60)
    print(f"  File     : {filepath}")
    print(f"  Size     : {os.path.getsize(filepath)} bytes")
    print(f"  Analysed : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("-"*60)
    for algo, value in hashes.items():
        print(f"  {algo:<10}: {value}")
    print("="*60)
    print("  Compare SHA-256 at: https://www.virustotal.com")
    print("  Or MalwareBazaar:  https://bazaar.abuse.ch\n")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python hash_analyser.py ")
        sys.exit(0)
    hashes = calculate_hashes(sys.argv[1])
    print_report(sys.argv[1], hashes)
    if len(sys.argv) == 3:
        known = sys.argv[2]
        match = hashes.get("SHA-256", "").lower() == known.lower()
        print("[MATCH]" if match else "[NO MATCH] — file may be modified or unknown")
