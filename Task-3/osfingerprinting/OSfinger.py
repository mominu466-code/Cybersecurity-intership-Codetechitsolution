import requests
import socket
import os

REPORT_FOLDER = "OSreport"
COMMON_PORTS = [21, 22, 23, 80, 443, 8080]

def init_folder():
    if not os.path.exists(REPORT_FOLDER):
        os.makedirs(REPORT_FOLDER)
        print(f"\n[+] Report folder created → {REPORT_FOLDER}")

def port_probe(ip):
    open_ports = []

    for port in COMMON_PORTS:
        try:
            sock = socket.create_connection((ip, port), timeout=1)
            open_ports.append(port)
            sock.close()
        except:
            pass

    return open_ports

def fingerprint(target):

    result = {
        "target": target,
        "ip": "Unknown",
        "open_ports": [],
        "server": "Unknown",
        "score": 0,
        "grade": "ERROR",
        "findings": ["Scan failed"],
        "advice": ["Check network or target"],
        "summary": "Scan could not complete."
    }

    try:
        if not target.startswith("http"):
            target = "http://" + target

        host = target.replace("http://","").replace("https://","").split("/")[0]
        ip = socket.gethostbyname(host)

        result["ip"] = ip
        result["open_ports"] = port_probe(ip)

        try:
            r = requests.get(target, timeout=4)
            result["server"] = r.headers.get("Server", "Unknown")
        except:
            result["server"] = "No HTTP service"

        score = len(result["open_ports"]) * 10
        result["score"] = score

        if score < 20:
            result["grade"] = "A"
        elif score < 40:
            result["grade"] = "B"
        elif score < 60:
            result["grade"] = "C"
        else:
            result["grade"] = "D"

        result["findings"] = [f"Open ports: {result['open_ports']}"]
        result["advice"] = ["Close unused ports"]
        result["summary"] = f"Exposure score {score}/100. Grade {result['grade']}."

    except Exception as e:
        result["summary"] = f"Error: {str(e)}"

    return result

def unique_filename(name):

    base = f"{REPORT_FOLDER}/{name}.html"

    if not os.path.exists(base):
        return base

    version = 2
    while True:
        new_name = f"{REPORT_FOLDER}/{name}_v{version}.html"
        if not os.path.exists(new_name):
            return new_name
        version += 1

def save_report(result):

    name = input("\nReport name (without .html): ").strip()

    if not name:
        name = "report"

    path = unique_filename(name)

    html = f"""
    <html>
    <body style="background:#111;color:white;font-family:Arial;padding:30px;">
    <h1>Security Exposure Report</h1>

    <b>Target:</b> {result['target']}<br>
    <b>IP:</b> {result['ip']}<br>
    <b>Server:</b> {result['server']}<br>
    <b>Score:</b> {result['score']}<br>
    <b>Grade:</b> {result['grade']}<br>

    <h3>Summary</h3>
    {result['summary']}

    <h3>Findings</h3>
    {"<br>".join(result['findings'])}

    <h3>Advice</h3>
    {"<br>".join(result['advice'])}

    </body></html>
    """

    with open(path, "w", encoding="utf-8") as f:
        f.write(html)

    print("\nReport saved →", path)

def run():

    print("\n=== Security Exposure Analyzer ===\n")

    init_folder()

    targets = input("Targets (comma separated): ").split(",")

    for t in targets:
        t = t.strip()

        print(f"\nScanning → {t}")

        result = fingerprint(t)

        print("Result:")
        for k, v in result.items():
            print(k, ":", v)

        save_report(result)

if __name__ == "__main__":
    run()
