# Task 4 – Advanced Encryption Vault

## Description

This project is a secure file encryption vault built using AES-256
authenticated encryption (AES-GCM).

It allows users to encrypt, decrypt, securely delete, and restore files
with password protection and vault management features.

This simulates a real-world secure storage system.

---

## Features

- AES-256 encryption (AES-GCM authenticated mode)
- Password-based key derivation (PBKDF2)
- Master vault password login
- Change / reset vault password
- Secure file trash system
- Encrypted file restore
- Auto metadata protection
- Strong random salt & nonce generation
- CLI vault dashboard
- Secure password input (hidden typing)

---

## Security Architecture

Encryption uses:

AES-GCM → authenticated encryption  
PBKDF2 → key derivation (150,000 iterations)  
Random salt + nonce per file  
SHA-256 vault password hashing  

Files are encrypted with independent keys.

---

## Requirements

Python 3.x

Install dependency:

pip install cryptography

---

## How to Run

python aes.py

You will be prompted for a vault password.

Default password:

vault123

(Change it immediately after login.)

---

## Vault Menu

1 → Encrypt file  
2 → Decrypt file  
3 → Send file to encrypted trash  
4 → Restore file  
5 → Change vault password  
6 → Reset vault password  
7 → Exit

---

## Usage Workflow

Encrypt:
Enter file path → enter file password → encrypted file created

Trash:
File is encrypted and moved to vault trash

Restore:
Select encrypted file → decrypt back to original

---

## Vault Storage

Encrypted trash folder:

.vault_trash/

Password hash file:

.vault_pass

These simulate secure vault storage behavior.

---

## Security Notes

- If file password is lost → file cannot be recovered
- Each file uses unique encryption salt
- AES-GCM protects against tampering
- Password reset does not decrypt existing files
- Use strong passwords

---

## Example Workflow

Login → Encrypt file → Trash file → Restore → Decrypt

This simulates secure digital vault operations.

---

## Author

Your Name
Cyber Security Internship – CODTECH
