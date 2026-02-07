# Task 3 – Penetration Testing Toolkit

## Description

This toolkit is a modular penetration testing suite that combines
multiple security tools into a single launcher interface.

The launcher allows the user to select and execute different tools
from one central dashboard.

Modules included:

1. Brute Force Analyzer
2. OS Fingerprint Analyzer
3. Enterprise Port Scanner

The toolkit simulates a real-world security testing environment.

---

## Toolkit Architecture

launcher.py → main dashboard

It connects to:

bruteforce/        → authentication security tester  
osfingerprinting/  → exposure & fingerprint analyzer  
portscanner/       → threaded port scanner  

Each module runs independently but is controlled by the launcher.

---

## Features

- Central launcher interface
- Modular architecture
- Threaded port scanning
- OS fingerprint detection
- Authentication brute-force analysis
- Automated HTML reports
- Risk scoring
- Banner grabbing
- Exploit matching
- Dashboard summary

---

## Requirements

Python 3.x

Install dependencies:

pip install requests

(Standard libraries are used for networking and threading)

---

## How to Run Launcher

python launcher.py

You will see:

1 → Brute Force Analyzer  
2 → Fingerprint Analyzer  
3 → Port Scanner  
0 → Exit

Select a module to launch.

---

## Module Usage Guide

### 1. Brute Force Analyzer

Purpose:
Tests authentication endpoints for rate limiting and lockout weaknesses.

Steps:
- Choose module 1
- Enter target URL
- Enter username
- Enter incorrect password
- Choose number of attempts
- Choose delay
- Tool generates HTML risk report

Report folder:
BFreport/

---

### 2. OS Fingerprint Analyzer

Purpose:
Identifies exposed services and estimates system risk.

Steps:
- Choose module 2
- Enter target domain/IP
- Scanner probes common ports
- Generates exposure score
- Saves HTML report

Report folder:
OSreport/

---

### 3. Enterprise Port Scanner

Purpose:
High-speed threaded port scanner with banner detection.

Steps:
- Choose module 3
- Enter target IP/domain
- Enter port range (example: 1-1000)
- Scanner runs multi-threaded scan
- Generates full security report

Report folder:
reports/

---

## Output Reports

Each module generates professional HTML security reports including:

- Findings
- Risk rating
- Technical summary
- Recommended fixes

These reports simulate real pentest deliverables.

---

## Security Notice

Use this toolkit only on systems you own or have permission to test.

Unauthorized scanning may violate laws and regulations.

This project is for educational and ethical hacking purposes only.

---

## Example Workflow

Open launcher → select module → run scan → generate report

This replicates a real penetration testing engagement.

---

## Author

Your Name
Cyber Security Internship – CODTECH
