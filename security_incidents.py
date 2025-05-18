import csv
from datetime import datetime
import os

# 偵測用的關鍵字列表
suspicious_keywords = [
    "unauthorized", "failed login", "sql injection", "malware"
]

# 讀取 log 檔案
with open("system_log.txt", "r") as logfile:
    lines = logfile.readlines()
    
# 準備 CSV 檔案
filename = 'security_incidents_log.csv'
file_exists = os.path.isfile(filename)

with open(filename, mode='a', newline='') as file:
    writer = csv.writer(file)
    if not file_exists:
        writer.writerow(['日期時間', '偵測事件', '受影響系統', '狀態', '備註'])

    for line in lines:
        for keyword in suspicious_keywords:
            if keyword.lower() in line.lower():
                now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                event = f"偵測到可疑活動: {keyword}"
                system = "Unknown System"
                status = "需處理"
                notes = line.strip()
                writer.writerow([now, event, system, status, notes])
                print(f"[!] 偵測到: {event} -> 已寫入 log")

print("掃描完成。 ")