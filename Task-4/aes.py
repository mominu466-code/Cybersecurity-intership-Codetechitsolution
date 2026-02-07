import os
import secrets
import getpass
import time
import hashlib
import sys
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

TRASH = ".vault_trash"
PASSFILE = ".vault_pass"
AUTO_DELETE = 60
DEFAULT_PASS = "vault123"

os.makedirs(TRASH, exist_ok=True)

# ---------- Password storage ----------
def load_hash():
    if not os.path.exists(PASSFILE):
        h = hashlib.sha256(DEFAULT_PASS.encode()).hexdigest()
        with open(PASSFILE, "w") as f:
            f.write(h)
        return h
    return open(PASSFILE).read().strip()

def save_hash(pwd):
    h = hashlib.sha256(pwd.encode()).hexdigest()
    with open(PASSFILE, "w") as f:
        f.write(h)

MASTER_HASH = load_hash()

# ---------- Color ----------
def green(x): return f"\033[92m{x}\033[0m"
def red(x): return f"\033[91m{x}\033[0m"
def cyan(x): return f"\033[96m{x}\033[0m"

# ---------- Safe input ----------
def safe_input(msg):
    try:
        return input(msg)
    except KeyboardInterrupt:
        print("\nExit")
        sys.exit()

# ---------- Login ----------
def login():
    pwd = getpass.getpass("Vault password: ")
    return hashlib.sha256(pwd.encode()).hexdigest() == load_hash()

# ---------- Change password ----------
def change_password():
    old = getpass.getpass("Current password: ")
    if hashlib.sha256(old.encode()).hexdigest() != load_hash():
        print(red("Wrong password"))
        return

    new = getpass.getpass("New password: ")
    confirm = getpass.getpass("Confirm: ")

    if new != confirm:
        print(red("Mismatch"))
        return

    save_hash(new)
    print(green("Password updated"))

# ---------- Reset password ----------
def reset_password():
    print(red("Reset → back to default"))
    save_hash(DEFAULT_PASS)
    print(green("Password reset to default"))

# ---------- Crypto ----------
def derive(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=150000
    )
    return kdf.derive(password.encode())

def encrypt_file(path, pwd, out=None):
    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(12)
    key = derive(pwd, salt)

    with open(path, "rb") as f:
        data = f.read()

    aes = AESGCM(key)
    encrypted = aes.encrypt(nonce, data, None)

    out = out or path + ".enc"
    with open(out, "wb") as f:
        f.write(salt + nonce + encrypted)

def decrypt_file(path, pwd, out=None):
    with open(path, "rb") as f:
        raw = f.read()

    salt = raw[:16]
    nonce = raw[16:28]
    data = raw[28:]

    key = derive(pwd, salt)
    aes = AESGCM(key)
    decrypted = aes.decrypt(nonce, data, None)

    out = out or path.replace(".enc", "")
    with open(out, "wb") as f:
        f.write(decrypted)

# ---------- Vault trash ----------
def vault_delete(path, pwd):
    name = os.path.basename(path) + ".enc"
    trash_path = os.path.join(TRASH, name)

    encrypt_file(path, pwd, trash_path)
    os.remove(path)

    with open(trash_path + ".time", "w") as f:
        f.write(str(time.time()))

    print(green("[+] Sent to trash"))

# ---------- Restore ----------
def restore(pwd):
    files = [f for f in os.listdir(TRASH) if f.endswith(".enc")]

    if not files:
        print("Trash empty")
        return

    for i, f in enumerate(files, 1):
        print(f"{i}. {f}")

    try:
        choice = int(safe_input("Restore #: ")) - 1
        target = files[choice]
    except:
        print("Invalid choice")
        return

    src = os.path.join(TRASH, target)
    out = target.replace(".enc", "")

    decrypt_file(src, pwd, out)
    os.remove(src)
    os.remove(src + ".time")

    print(green("[+] Restored"))

# ---------- CLI ----------
def banner():
    print(cyan("\n=== Vault User Mode ==="))
    print("1. Encrypt")
    print("2. Decrypt")
    print("3. Trash file")
    print("4. Restore")
    print("5. Change password")
    print("6. Reset password")
    print("7. Exit")

def main():
    if not login():
        print(red("Wrong password"))
        return

    while True:
        banner()
        choice = safe_input("Select: ")

        if choice == "7":
            break

        if choice == "5":
            change_password()
            continue

        if choice == "6":
            reset_password()
            continue

        if choice == "4":
            pwd = getpass.getpass("File password: ")
            restore(pwd)
            continue

        target = safe_input("Path: ")

        if not os.path.exists(target):
            print(red("Invalid path"))
            continue

        pwd = getpass.getpass("File password: ")

        if choice == "3":
            vault_delete(target, pwd)
        elif choice == "1":
            encrypt_file(target, pwd)
        elif choice == "2":
            decrypt_file(target, pwd)

        print(green("Done ✔"))

if __name__ == "__main__":
    main()
