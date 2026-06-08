# Security Scripts — Python Tools for SOC Operations

Python scripts built as part of my SOC home lab. Each solves a real security operations problem.

## Scripts

| Script | Purpose | Security Use Case |
|--------|---------|------------------|
| hash_analyser.py | Compare MD5, SHA-256, SHA-512 hashes | Malware identification, file integrity |
| file_integrity_monitor.py | Monitor files for unauthorised changes | Detect tampering, persistence mechanisms |
| log_parser.py | Parse Windows Event Logs for suspicious Event IDs | SOC triage automation |

## Tools & Libraries
Python 3 | hashlib | os | socket | re | datetime | json

## Author
Tanay Shirsat — SOC Analyst | github.com/tanayshirsat
