import hashlib
import os
import difflib
import time
import glob
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.pagesizes import A4
from reportlab.lib.enums import TA_LEFT
from reportlab.lib import colors

# ================= TAB AUTOCOMPLETE =================
try:
    import readline
except ImportError:
    import pyreadline3 as readline

def path_completer(text, state):
    return glob.glob(text + '*')[state]

readline.set_completer(path_completer)
readline.parse_and_bind("tab: complete")

# ================= PDF HASH STYLE =================
hash_style = ParagraphStyle(
    name="HashStyle",
    fontName="Courier",
    fontSize=9,
    leading=11,
    wordWrap="CJK",
    alignment=TA_LEFT
)

# ================= HASH =================
def calculate_hash(file_path, algo="sha256"):
    h = hashlib.new(algo)
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            h.update(chunk)
    return h.hexdigest()

# ================= METADATA =================
def get_metadata(file_path):
    return {
        "size": os.path.getsize(file_path),
        "modified": time.ctime(os.path.getmtime(file_path))
    }

# ================= ACTION COUNTER =================
def next_action_no(log_path):
    if not os.path.exists(log_path):
        return 1
    with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
        return f.read().count("ACTION:") + 1

# ================= SNAPSHOT =================
def extract_original_snapshot(text):
    if "ORIGINAL CONTENT SNAPSHOT" not in text:
        return []
    part = text.split("ORIGINAL CONTENT SNAPSHOT")[1]
    lines = part.splitlines(keepends=True)
    clean = []
    for l in lines:
        if l.startswith("========== ACTION"):
            break
        clean.append(l)
    return clean

# ================= DIFF =================
def get_changes(old, new):
    removed, added = [], []
    for d in difflib.ndiff(old, new):
        if d.startswith("- "):
            removed.append(d[2:].rstrip())
        elif d.startswith("+ "):
            added.append(d[2:].rstrip())
    return removed, added

# ================= PDF: ACTIVITY LOG (OPTION-B) =================
def pdf_activity_log(txt, pdf):
    styles = getSampleStyleSheet()
    doc = SimpleDocTemplate(pdf, pagesize=A4)
    story = [
        Paragraph("<b>ACTIVITY LOG – FORENSIC TIMELINE</b>", styles["Title"]),
        Spacer(1, 14)
    ]

    with open(txt, "r", encoding="utf-8", errors="ignore") as f:
        current = {}

        for line in f:
            line = line.strip()

            if line.startswith("ACTION:"):
                current["Action No"] = line.split(":", 1)[1]

            elif line.startswith("TYPE:"):
                current["Type"] = line.split(":", 1)[1]

            elif line.startswith("TIME:"):
                current["Time"] = line.split(":", 1)[1]

            elif line.startswith("STATUS:"):
                current["Status"] = line.split(":", 1)[1]

            elif line.startswith("HASH:"):
                current["Hash"] = line.split(":", 1)[1]

            elif line.startswith("SIZE:"):
                current["Size"] = line.split(":", 1)[1]

                # ===== ACTION COMPLETE =====
                story.append(
                    Paragraph(
                        f"<b>ACTION {current.get('Action No','')}</b>",
                        styles["Heading1"]
                    )
                )
                story.append(Spacer(1, 6))

                table_data = []
                for key in ["Type", "Time", "Status", "Hash", "Size"]:
                    val = current.get(key, "")
                    if key == "Hash":
                        table_data.append([key, Paragraph(val, hash_style)])
                    else:
                        table_data.append([key, val])

                table = Table(table_data, colWidths=[120, 340])
                table.setStyle(TableStyle([
                    ("GRID", (0,0), (-1,-1), 1, colors.black),
                    ("BACKGROUND", (0,0), (-1,0), colors.lightgrey),
                    ("VALIGN", (0,0), (-1,-1), "TOP"),
                ]))

                story.append(table)
                story.append(Spacer(1, 22))
                current = {}

    doc.build(story)

# ================= PDF: INTEGRITY RECORD =================
def pdf_integrity_record(txt, pdf):
    styles = getSampleStyleSheet()
    doc = SimpleDocTemplate(pdf, pagesize=A4)
    story = []

    with open(txt, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.read().splitlines()

    original_snapshot = []
    i = 0
    while i < len(lines):
        if lines[i].startswith("ORIGINAL CONTENT SNAPSHOT"):
            i += 1
            while i < len(lines) and not lines[i].startswith("========== ACTION"):
                original_snapshot.append(lines[i])
                i += 1
            break
        i += 1

    i = 0
    while i < len(lines):
        if lines[i].startswith("========== ACTION"):
            story.append(Paragraph("<b>ACTION DETAILS</b>", styles["Heading1"]))
            story.append(Spacer(1, 8))
            i += 1

            details = []
            while i < len(lines) and not lines[i].startswith("REMOVED CONTENT"):
                if ":" in lines[i]:
                    k, v = lines[i].split(":", 1)
                    if "Hash" in k:
                        details.append([k.strip(), Paragraph(v.strip(), hash_style)])
                    else:
                        details.append([k.strip(), v.strip()])
                i += 1

            table = Table(details, colWidths=[140, 360])
            table.setStyle(TableStyle([
                ("GRID",(0,0),(-1,-1),1,colors.black),
                ("BACKGROUND",(0,0),(-1,0),colors.lightgrey),
                ("VALIGN",(0,0),(-1,-1),"TOP")
            ]))
            story.append(table)
            story.append(Spacer(1, 12))

            removed, added = [], []

            if i < len(lines) and lines[i].startswith("REMOVED CONTENT"):
                i += 1
                while i < len(lines) and not lines[i].startswith("ADDED CONTENT"):
                    if lines[i].strip():
                        removed.append(lines[i])
                    i += 1

            if i < len(lines) and lines[i].startswith("ADDED CONTENT"):
                i += 1
                while i < len(lines) and not lines[i].startswith("========== ACTION"):
                    if lines[i].strip():
                        added.append(lines[i])
                    i += 1

            story.append(Paragraph("<b>REMOVED CONTENT</b>", styles["Heading2"]))
            for r in removed or ["[None]"]:
                story.append(Paragraph(r, styles["Normal"]))

            story.append(Spacer(1, 10))

            story.append(Paragraph("<b>ADDED CONTENT</b>", styles["Heading2"]))
            for a in added or ["[None]"]:
                story.append(Paragraph(a, styles["Normal"]))

            story.append(Spacer(1, 12))
            story.append(Paragraph("<b>ORIGINAL SNAPSHOT (REFERENCE)</b>", styles["Heading2"]))
            for line in original_snapshot:
                story.append(Paragraph(line, styles["Normal"]))

            story.append(PageBreak())
            continue
        i += 1

    doc.build(story)

# ================= BASE =================
base = input("Enter data folder (default=data): ").strip() or "data"
os.makedirs(base, exist_ok=True)

# ================= MENU =================
while True:
    print("\n1. Create Baseline\n2. Check File\n3. Exit")
    ch = input("Choose: ").strip()
    if ch == "3":
        break

    path = os.path.abspath(input("Enter file path: ").strip('"'))
    if not os.path.exists(path):
        print("File not found")
        continue

    name = os.path.basename(path)
    folder = os.path.join(base, name)
    os.makedirs(folder, exist_ok=True)

    act_log = os.path.join(folder, "activity_log.txt")
    int_log = os.path.join(folder, "integrity_record.txt")

    h = calculate_hash(path)
    meta = get_metadata(path)
    t = time.ctime()
    act = next_action_no(act_log)

    # ===== CREATE BASELINE =====
    if ch == "1":
        with open(int_log, "a", encoding="utf-8", errors="replace") as f:
            if act == 1:
                f.write("========== ORIGINAL BASELINE ==========\n")
                f.write(f"Time : {t}\nHash : {h}\n\n")
                f.write("ORIGINAL CONTENT SNAPSHOT\n")
                with open(path, "r", encoding="utf-8", errors="ignore") as r:
                    f.writelines(r.readlines())

            f.write(f"\n========== ACTION {act} ==========\n")
            f.write("Type : BASELINE CREATED\n")
            f.write(f"Time : {t}\n")

        with open(act_log, "a", encoding="utf-8", errors="replace") as a:
            a.write(
                f"ACTION:{act}\nTYPE:CREATE BASELINE\nTIME:{t}\n"
                f"STATUS:CREATED\nHASH:{h}\nSIZE:{meta['size']}\n\n"
            )
        print("Baseline created")

    # ===== CHECK FILE =====
    if ch == "2":
        with open(int_log, "r", encoding="utf-8", errors="ignore") as f:
            base_txt = f.read()

        status = "UNCHANGED" if h in base_txt else "MODIFIED"

        with open(act_log, "a", encoding="utf-8", errors="replace") as a:
            a.write(
                f"ACTION:{act}\nTYPE:CHECK FILE\nTIME:{t}\n"
                f"STATUS:{status}\nHASH:{h}\nSIZE:{meta['size']}\n\n"
            )

        if status == "MODIFIED":
            old = extract_original_snapshot(base_txt)
            with open(path, "r", encoding="utf-8", errors="ignore") as r:
                new = r.readlines()

            rem, add = get_changes(old, new)

            with open(int_log, "a", encoding="utf-8", errors="replace") as f:
                f.write(f"\n========== ACTION {act} ==========\n")
                f.write("Type : FILE MODIFIED\n")
                f.write(f"Time : {t}\nNew Hash : {h}\n")
                f.write("\nREMOVED CONTENT\n")
                for x in rem or ["[None]"]:
                    f.write(x + "\n")
                f.write("\nADDED CONTENT\n")
                for x in add or ["[None]"]:
                    f.write(x + "\n")

        print("File check:", status)

    # ===== SAVE FORMAT =====
    print("\nSave output as:\n1. TXT\n2. PDF\n3. Both")
    s = input("Select: ").strip()

    if s in ["2", "3"]:
        if os.path.exists(act_log):
            pdf_activity_log(act_log, os.path.join(folder, "activity_log.pdf"))
        if os.path.exists(int_log):
            pdf_integrity_record(int_log, os.path.join(folder, "integrity_record.pdf"))
        print("PDF export completed")
