# Task 1 – File Integrity Checker

## Description

This tool monitors file integrity by creating a baseline hash and comparing
future versions of the file. It detects modifications and generates a
forensic timeline showing what changed.

The tool supports:

- SHA-256 hashing
- Baseline snapshot creation
- File modification detection
- Content difference tracking
- Activity logs
- Integrity records
- PDF forensic reports

It is designed for digital forensics and integrity auditing.

---

## Features

- Create original file baseline
- Detect file tampering
- Line-by-line change detection
- Activity timeline logging
- Metadata tracking (size + modification time)
- TXT log generation
- Professional PDF forensic reports
- Automatic folder organization
- Tab autocomplete for file paths

---

## Requirements

Python 3.x

Install required libraries:

pip install reportlab

Standard libraries used:
hashlib, os, difflib, time, glob

---

## How to Run

python file_integrity.py

---

## Usage

1. Enter a folder name for storing records (default: data)
2. Choose an option:

   1 → Create baseline  
   2 → Check file integrity  
   3 → Exit

3. Enter file path
4. Select output format:
   TXT / PDF / Both

The tool automatically creates logs inside a dedicated folder.

---

## Output Files

For each monitored file:

- activity_log.txt → timeline of actions
- integrity_record.txt → change details
- activity_log.pdf → forensic report
- integrity_record.pdf → integrity report

All files are stored inside:

data/<filename>/

---

## Security Notes

- Baseline must be created before integrity checking
- Original snapshot is preserved for forensic comparison
- PDF reports are read-only evidence records
- SHA-256 ensures strong tamper detection

---

## Example Workflow

Create baseline → Modify file → Run check → See differences → Export PDF

This simulates real-world digital forensics integrity verification.

---

## Author

Your Name
Cyber Security Internship – CODTECH
