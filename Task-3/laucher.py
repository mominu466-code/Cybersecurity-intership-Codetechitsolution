import os
import subprocess
import time

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

MODULES = [
    {
        "name": "Brute Force Analyzer",
        "folder": "bruteforce",
        "script": "bruteforce.py",
        "desc": "Authentication security tester"
    },
    {
        "name": "Fingerprint Analyzer",
        "folder": "osfingerprinting",
        "script": "OSfinger.py",
        "desc": "Exposure & system fingerprinting"
    },
    {
        "name": "Port Scanner",
        "folder": "portscanner",
        "script": "port_scanner.py",
        "desc": "Enterprise threaded port scan"
    }
]

def clear():
    os.system("cls" if os.name == "nt" else "clear")

def banner():
    print("""
====================================
        PENTEST TOOLKIT v2
====================================
""")

def run_module(module):

    tool_dir = os.path.join(BASE_DIR, module["folder"])
    script = module["script"]
    script_path = os.path.join(tool_dir, script)

    if not os.path.exists(script_path):
        print(f"\n❌ Module missing → {script_path}")
        input("Press Enter...")
        return

    print(f"\n🚀 Launching {module['name']}...\n")

    try:
        subprocess.run(["python", script], cwd=tool_dir)
    except Exception as e:
        print("Execution error:", e)

    input("\nReturn to toolkit → press Enter")

def menu():

    while True:
        clear()
        banner()

        for i, m in enumerate(MODULES, 1):
            print(f"{i}. {m['name']}")
            print(f"   ↳ {m['desc']}\n")

        print("0. Exit\n")

        choice = input("Select module: ").strip()

        if choice == "0":
            print("\nExiting toolkit 👋")
            time.sleep(1)
            break

        if choice.isdigit() and 1 <= int(choice) <= len(MODULES):
            run_module(MODULES[int(choice)-1])
        else:
            print("Invalid choice")
            time.sleep(1)

if __name__ == "__main__":
    menu()
