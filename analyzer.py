from collections import defaultdict, deque
from Evtx.Evtx import Evtx
import xml.etree.ElementTree as ET
import csv
import time
import os


log_file = "Logs/logs_real.evtx"

# -----------------------------
# STORAGE
# -----------------------------
ip_user_map = defaultdict(set)
attack_window = defaultdict(deque)
ip_risk_score = defaultdict(int)

# -----------------------------
# CONFIG
# -----------------------------
TIME_WINDOW = 60
FAILED_THRESHOLD = 5


# -----------------------------
# HELPERS (FILTERING)
# -----------------------------
def classify_ip(ip):

    if not ip or ip == "-":
        return "unknown"

    if ip in ["127.0.0.1", "::1"]:
        return "localhost"

    if ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172.16."):
        return "internal"

    return "external"



def extract_fields(root):

    event_id = None
    username = None
    ip_address = None
    timestamp = None

    for elem in root.iter():

        if elem.tag.endswith("EventID"):
            event_id = elem.text

        if elem.tag.endswith("TimeCreated"):
            timestamp = elem.attrib.get("SystemTime")

    for data in root.iter():

        if data.tag.endswith("Data"):

            name = data.attrib.get("Name")

            if name == "TargetUserName":
                username = data.text

            elif name == "IpAddress":
                ip_address = data.text

    return event_id, username, ip_address, timestamp


# -----------------------------
# THREAT ENGINE
# -----------------------------
def analyze_event(event_id, ip, user, timestamp):

    ip_type = classify_ip(ip)

    # ❗ DO NOT DROP EVENTS — just deprioritize noise
    if ip_type == "unknown":
        return

    current_time = time.time()

    # -------------------------
    # FAILED LOGIN (4625)
    # -------------------------
    if event_id == "4625":

        ip_user_map[ip].add(user)

        # only track brute force for external/internal (not localhost noise)
        if ip_type in ["internal", "external"]:

            attack_window[ip].append(current_time)

            # remove old timestamps
            while attack_window[ip] and current_time - attack_window[ip][0] > TIME_WINDOW:
                attack_window[ip].popleft()

            count = len(attack_window[ip])

            if count >= FAILED_THRESHOLD:

                ip_risk_score[ip] += 50
                print(f"\n🚨 BRUTE FORCE DETECTED")
                print(f"IP: {ip} ({ip_type}) | Attempts: {count}")

            else:

                ip_risk_score[ip] += 10
                print(f"❌ Failed login | IP: {ip} ({ip_type})")

        else:

            
            ip_risk_score[ip] += 1


    # -------------------------
    # SUCCESS LOGIN (4624)
    # -------------------------
    elif event_id == "4624":

        ip_user_map[ip].add(user)

        if ip_type == "external":
            ip_risk_score[ip] -= 5
        elif ip_type == "internal":
            ip_risk_score[ip] -= 1

        print(f"✅ Successful login | IP: {ip} ({ip_type})")


# -----------------------------
# REPORT GENERATOR
# -----------------------------
def generate_report():

    print("\n\n====== SOC SECURITY REPORT ======\n")

    os.makedirs("Reports", exist_ok=True)

    with open("Reports/threat-report.csv", "w", newline="") as file:

        writer = csv.writer(file)
        writer.writerow(["IP", "Risk Score", "Users", "Type", "Level"])

        for ip, score in ip_risk_score.items():

            ip_type = classify_ip(ip)
            users = ", ".join(ip_user_map[ip])

            if score >= 70:
                level = "HIGH RISK"
            elif score >= 30:
                level = "MEDIUM RISK"
            else:
                level = "LOW RISK"

            print(f"IP: {ip} | Score: {score} | Type: {ip_type} | Level: {level} | Users: {users}")

            writer.writerow([ip, score, users, ip_type, level])


# -----------------------------
# MAIN EXECUTION
# -----------------------------
with Evtx(log_file) as evtx:

    for record in evtx.records():

        xml_data = record.xml()
        root = ET.fromstring(xml_data)

        event_id, username, ip_address, timestamp = extract_fields(root)

        analyze_event(event_id, ip_address, username, timestamp)


generate_report()