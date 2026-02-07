import requests
import time
import webbrowser
import os
from statistics import mean
from datetime import datetime

REPORT_FOLDER = "BFreport"

# -----------------------------
# Core scanner (your engine)
# -----------------------------

def fix_url(url):
    if not url.startswith("http"):
        return "http://" + url
    return url

def progress(i, total):
    percent = int((i / total) * 100)
    bar = "█" * (percent // 10) + "░" * (10 - percent // 10)
    print(f"[{bar}] {percent}% ", end="\r")

def test_connection(url):
    try:
        requests.get(url, timeout=3)
        return True
    except:
        return False

def scan_target(target, username, password, attempts, delay):

    target = fix_url(target)

    if not test_connection(target):
        print("Target unreachable")
        return None

    times = []
    codes = []
    lockout = False
    risk = 0
    findings = []
    advice = []

    print(f"\nScanning {target}")

    for i in range(1, attempts + 1):
        start = time.time()

        r = requests.post(target, data={
            "username": username,
            "password": password
        })

        elapsed = time.time() - start
        times.append(elapsed)
        codes.append(r.status_code)

        if r.status_code in [403, 429]:
            lockout = True

        progress(i, attempts)
        time.sleep(delay)

    print()

    avg = mean(times)

    if avg < 0.25:
        findings.append("Weak rate limiting")
        advice.append("Add throttling / exponential backoff")
        risk += 30
    else:
        findings.append("Rate limiting active")

    if not lockout:
        findings.append("No account lockout")
        advice.append("Lock account after repeated failures")
        risk += 30
    else:
        findings.append("Lockout protection active")

    if len(set(codes)) > 1:
        findings.append("Inconsistent error responses")
        advice.append("Use uniform authentication errors")
        risk += 20

    spread = max(times) - min(times)
    if spread > 0.5:
        findings.append("Timing variation detected")
        advice.append("Normalize response timing")
        risk += 20

    risk_score = min(risk, 100)

    if risk_score < 30:
        level = "LOW"
        color = "#2ecc71"
    elif risk_score < 60:
        level = "MEDIUM"
        color = "#f1c40f"
    else:
        level = "HIGH"
        color = "#e74c3c"

    summary = f"Risk {level} ({risk_score}/100)"

    return {
        "target": target,
        "avg": round(avg, 3),
        "risk_score": risk_score,
        "level": level,
        "color": color,
        "summary": summary,
        "findings": findings,
        "advice": advice
    }

# -----------------------------
# Reporting
# -----------------------------

def save_report(result):

    os.makedirs(REPORT_FOLDER, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    name = result["target"].replace("http://","").replace("https://","").replace("/","_")

    filename = f"{REPORT_FOLDER}/{name}_{timestamp}.html"

    html = f"""
    <html>
    <body style="background:#111;color:white;font-family:Arial;padding:30px;">
    <h1>Auth Security Report</h1>

    <h2>{result['target']}</h2>
    <b>Risk:</b> <span style="color:{result['color']}">{result['summary']}</span><br>
    <b>Average Response:</b> {result['avg']} sec

    <h3>Findings</h3>
    {"<br>".join(result['findings'])}

    <h3>Recommended Fixes</h3>
    {"<br>".join(result['advice'])}

    </body></html>
    """

    with open(filename, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"\nReport saved → {filename}")
    webbrowser.open(filename)

# -----------------------------
# CLI shell wrapper
# -----------------------------

def show_help():
    print("""
Commands:
 scan     → run auth scan
 reports  → open report folder
 help     → show commands
 exit     → quit
""")

def cli():

    print("\n=== Brute Force Toolkit CLI ===")
    print("Type 'help' for commands\n")

    while True:

        cmd = input("bf> ").strip().lower()

        if cmd == "exit":
            break

        elif cmd == "help":
            show_help()

        elif cmd == "reports":
            os.makedirs(REPORT_FOLDER, exist_ok=True)
            os.startfile(REPORT_FOLDER)

        elif cmd == "scan":

            target = input("Target URL: ")
            username = input("Username: ")
            password = input("Wrong password: ")
            attempts = int(input("Attempts: "))
            delay = float(input("Delay: "))

            result = scan_target(target, username, password, attempts, delay)

            if result:
                save_report(result)

        else:
            print("Unknown command")

# -----------------------------

if __name__ == "__main__":
    cli()
