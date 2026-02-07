import socket
import threading
import argparse
import os
from datetime import datetime
import sys

REPORT_FOLDER = "reports"
os.makedirs(REPORT_FOLDER, exist_ok=True)

open_ports = []
banners = {}
closed_count = 0
lock = threading.Lock()

EXPLOITS = {
    "OpenSSH_7": ("CVE-2018-15473", "HIGH"),
    "Apache/2.2": ("CVE-2017-5638", "CRITICAL"),
    "vsftpd 2.3.4": ("CVE-2011-2523", "CRITICAL")
}

OS_HINTS = {
    "Ubuntu": "Linux",
    "Debian": "Linux",
    "Microsoft": "Windows",
    "IIS": "Windows"
}

COMMON_SERVICES = {
    21: "ftp", 22: "ssh", 23: "telnet",
    80: "http", 443: "https", 445: "smb",
    3389: "rdp", 8080: "http-alt"
}

# -------------------------
# Core helpers
# -------------------------

def extract_version(text):
    for k in ["Apache", "nginx", "OpenSSH", "vsftpd", "Microsoft", "IIS"]:
        if k.lower() in text.lower():
            return text.strip()
    if "HTTP" in text:
        return "HTTP server detected"
    return "unknown"

def guess_os():
    combined = " ".join(banners.values())
    for k in OS_HINTS:
        if k.lower() in combined.lower():
            return OS_HINTS[k]
    return "unknown"

def match_exploit(banner):
    for sig in EXPLOITS:
        if sig in banner:
            return EXPLOITS[sig]
    return None

def grab_banner(sock, port):
    try:
        if port == 80:
            sock.send(b"GET / HTTP/1.1\r\nHost: test\r\n\r\n")
        elif port == 443:
            return "TLS/SSL detected"
        else:
            sock.send(b"HELLO\r\n")

        data = sock.recv(1024).decode(errors="ignore")
        return extract_version(data.split("\n")[0])
    except:
        return "unknown"

# -------------------------
# Scanner
# -------------------------

def scan_port(target, port, retries, detect_version):
    global closed_count
    success = 0

    for _ in range(retries):
        try:
            sock = socket.socket()
            sock.settimeout(1)
            if sock.connect_ex((target, port)) == 0:
                success += 1
            sock.close()
        except:
            pass

    if success > retries // 2:
        banner = "open"

        if detect_version:
            try:
                sock = socket.socket()
                sock.settimeout(1)
                sock.connect((target, port))
                banner = grab_banner(sock, port)
                sock.close()
            except:
                banner = "open"

        confidence = int((success / retries) * 100)

        with lock:
            open_ports.append(port)
            banners[port] = f"{banner} ({confidence}% confidence)"
    else:
        with lock:
            closed_count += 1

def risk_score():
    score = len(open_ports)
    for b in banners.values():
        if match_exploit(b):
            score += 5

    if score >= 10:
        return "HIGH"
    elif score >= 5:
        return "MEDIUM"
    return "LOW"

# -------------------------
# Dashboard + report
# -------------------------

def dashboard(target):
    print("\n===== SCAN DASHBOARD =====")
    print("Target:", target)
    print("Open Ports:", len(open_ports))
    print("Closed/Filtered:", closed_count)
    print("Detected OS:", guess_os())
    print("Overall Risk:", risk_score())
    print("==========================\n")

def final_report(target):
    name = os.path.join(REPORT_FOLDER, f"{target}_FULL_REPORT.html")

    with open(name, "w") as f:
        f.write("<html><body>")
        f.write("<h1>Enterprise Security Assessment Report</h1>")
        f.write(f"<p>Target: <b>{target}</b></p>")
        f.write(f"<p>Risk Level: <b>{risk_score()}</b></p>")

        f.write("<h2>Technical Findings</h2>")
        f.write("<table border=1>")
        f.write("<tr><th>Port</th><th>Service</th><th>Banner</th><th>Risk</th></tr>")

        for p in sorted(open_ports):
            service = COMMON_SERVICES.get(p, "unknown")
            banner = banners.get(p, "")
            exploit = match_exploit(banner)
            risk_level = exploit[1] if exploit else "INFO"

            f.write(f"<tr><td>{p}</td><td>{service}</td><td>{banner}</td><td>{risk_level}</td></tr>")

        f.write("</table></body></html>")

    print("Report saved:", name)

# -------------------------
# Scan runner
# -------------------------

def run_scan(target, start, end, args):

    global closed_count
    open_ports.clear()
    banners.clear()
    closed_count = 0

    retries = 5 if args.A else args.retry
    detect_version = args.sV or args.A

    print(f"\nScanning {target}...\n")
    start_time = datetime.now()

    threads = []

    for port in range(start, end + 1):
        t = threading.Thread(target=scan_port,
                             args=(target, port, retries, detect_version))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    dashboard(target)
    final_report(target)

    print("Time:", datetime.now() - start_time)

# -------------------------
# Interactive mode
# -------------------------

def interactive_mode():

    class Args:
        Pn = False
        sV = True
        A = False
        retry = 3

    while True:
        print("""
========================
    Port Scanner
========================

1. New Scan
2. Exit
""")

        choice = input("Select: ").strip()

        if choice == "2":
            break

        target = input("Target: ").strip()
        ports = input("Range (1-1000): ").strip()

        try:
            s, e = map(int, ports.split("-"))
        except:
            print("Invalid range")
            continue

        run_scan(target, s, e, Args())

# -------------------------
# Main entry
# -------------------------

def main():

    if len(sys.argv) == 1:
        interactive_mode()
        return

    parser = argparse.ArgumentParser()

    parser.add_argument("-t", "--target", required=True)
    parser.add_argument("-p", "--ports", default="1-100")
    parser.add_argument("-Pn", action="store_true")
    parser.add_argument("-sV", action="store_true")
    parser.add_argument("-A", action="store_true")
    parser.add_argument("--retry", type=int, default=3)

    args = parser.parse_args()

    s, e = map(int, args.ports.split("-"))
    run_scan(args.target, s, e, args)

if __name__ == "__main__":
    main()
