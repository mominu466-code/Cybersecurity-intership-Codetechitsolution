# Task 2 – Web Application Vulnerability Scanner

## Description

This tool scans web applications for common vulnerabilities such as:

- SQL Injection
- Cross-Site Scripting (XSS)

It supports both basic and advanced scanning modes and generates
professional vulnerability assessment reports in DOCX or PDF format.

The scanner simulates real-world web security testing and produces
evidence-based findings with severity ratings and remediation advice.

---

## Features

- SQL Injection detection
- XSS vulnerability detection
- Basic and Advanced scan modes
- URL parameter testing
- Form-based XSS testing
- Automated payload injection
- Severity classification
- Proof-of-Concept logging
- Professional DOCX reports
- Professional PDF reports
- Interactive dashboard interface
- Colored console output
- Findings management system

---

## Requirements

Python 3.x

Install dependencies:

pip install requests beautifulsoup4 python-docx reportlab colorama

---

## How to Run

python vuln_scanner.py

---

## Usage

1. Enter target URL
2. Choose scan mode:

   1 → Basic Scan  
   2 → Advanced Scan

3. Wait for scan results
4. Generate report (DOCX or PDF)
5. Save assessment

---

## Scan Modes

Basic Mode:
- Quick vulnerability detection
- Common payload testing

Advanced Mode:
- Deep payload testing
- Expanded attack vectors
- More aggressive scanning

---

## Report Output

Generated reports include:

- Target URL
- Scan timestamp
- Vulnerability type
- Severity rating
- Attack payload
- Proof of concept
- Security recommendation

Reports are saved inside:

data/

---

## Security Notes

- Use only on systems you own or have permission to test
- This tool is for ethical hacking and educational purposes
- Unauthorized scanning may be illegal

---

## Example Workflow

Enter URL → Run scan → Findings detected → Generate report

This simulates a real penetration testing engagement.

---

## Author

Your Name
Cyber Security Internship – CODTECH
