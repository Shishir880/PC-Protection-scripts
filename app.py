import os
import subprocess
import tkinter as tk
from tkinter import scrolledtext, messagebox
import psutil
import threading
import time
from PIL import ImageGrab, Image
import telegram
from ttkthemes import ThemedTk
import ttkbootstrap as ttk
import shutil
import math
from collections import Counter
import requests
import yara
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import pyotp
from scapy.all import sniff

# ✅ Telegram Alert Setup (Replace with your bot token and chat ID)
BOT_TOKEN = "https://api.telegram.org/bot123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11/getMe"
CHAT_ID = "5985821200"

# ✅ Global Variables
CURRENT_VERSION = "1.0.0"

# ✅ Telegram Alert Function
def send_alert(message, screenshot=False):
    bot = telegram.Bot(token=BOT_TOKEN)
    bot.send_message(chat_id=CHAT_ID, text=message)
    if screenshot:
        image = ImageGrab.grab()
        image.save("screenshot.jpg")
        bot.send_photo(chat_id=CHAT_ID, photo=open("screenshot.jpg", "rb"))

# ✅ Port Scanner
def scan_ports():
    result = subprocess.getoutput("netstat -ano")
    text_area.insert(tk.END, f"\n🔍 Open Ports:\n{result}\n")

# ✅ Spyware Detection
def detect_spyware():
    processes = subprocess.getoutput("tasklist")
    spyware_apps = ["zoom.exe", "teams.exe", "anydesk.exe"]
    for app in spyware_apps:
        if app in processes:
            text_area.insert(tk.END, f"\n⚠ Spyware Detected: {app}\n")
            send_alert(f"⚠ Spyware Detected: {app}")

# ✅ USB Monitor
def usb_monitor():
    prev_usb = set(psutil.disk_partitions())
    while True:
        current_usb = set(psutil.disk_partitions())
        new_usb = current_usb - prev_usb
        if new_usb:
            text_area.insert(tk.END, f"\n🚨 Unauthorized USB Detected!\n")
        time.sleep(5)

# ✅ AI Virus Scanner
def ai_virus_scanner():
    suspicious_files = [".exe", ".bat", ".vbs", ".dll"]
    virus_paths = ["C:/Users", "C:/Windows/System32"]
    for path in virus_paths:
        for root, dirs, files in os.walk(path):
            for file in files:
                if any(file.endswith(ext) for ext in suspicious_files):
                    text_area.insert(tk.END, f"\n🦠 Suspicious File: {file}\n")
                    send_alert(f"🦠 Virus Detected: {file}")

# ✅ Keylogger Detector
def keylogger_detector():
    keyloggers = ["keylogger.exe", "hook.dll", "logger.py"]
    processes = subprocess.getoutput("tasklist")
    for keylogger in keyloggers:
        if keylogger in processes:
            text_area.insert(tk.END, f"\n⚠ Keylogger Detected: {keylogger}\n")
            send_alert(f"⚠ Keylogger Detected: {keylogger}")
            os.system(f"taskkill /IM {keylogger} /F")

# ✅ Resource Monitor
def resource_monitor():
    while True:
        cpu = psutil.cpu_percent()
        ram = psutil.virtual_memory().percent
        disk = psutil.disk_usage('/').percent
        status_label.config(text=f"🔥 CPU: {cpu}%  |  RAM: {ram}%  |  DISK: {disk}%")
        time.sleep(2)

# ✅ Real-Time Malware Detection
def real_time_malware_detection():
    rules = yara.compile(filepath='malware_rules.yar')
    while True:
        for proc in psutil.process_iter(['pid', 'name']):
            matches = rules.match(proc.info['name'])
            if matches:
                text_area.insert(tk.END, f"\n🦠 Malware Detected: {proc.info['name']}\n")
        time.sleep(10)

# ✅ Firewall Monitoring
def check_firewall():
    status = subprocess.getoutput("netsh advfirewall show allprofiles state")
    text_area.insert(tk.END, f"\n🔥 Firewall Status:\n{status}\n")

# ✅ Ransomware Protection
class RansomwareHandler(FileSystemEventHandler):
    def on_modified(self, event):
        text_area.insert(tk.END, f"\n🚨 Suspicious File Modification: {event.src_path}\n")

def start_ransomware_protection():
    observer = Observer()
    observer.schedule(RansomwareHandler(), path="C:/", recursive=True)
    observer.start()

# # ✅ Password Strength Checker
# def check_password_strength(password):
#     result = zxcvbn(password)
#     text_area.insert(tk.END, f"\n🔐 Password Strength: {result['score']}/4\n")

# ✅ Browser Cache Cleaner
def clear_browser_cache():
    paths = ["C:/Users/Username/AppData/Local/Google/Chrome/User Data/Default/Cache"]
    for path in paths:
        if os.path.exists(path):
            shutil.rmtree(path)
            text_area.insert(tk.END, f"\n🧹 Cleared Browser Cache: {path}\n")

# ✅ System Vulnerability Scanner
def check_vulnerabilities():
    outdated = subprocess.getoutput("wmic qfe list full")
    text_area.insert(tk.END, f"\n🔓 System Vulnerabilities:\n{outdated}\n")

# ✅ Encrypted File Detection
def calculate_entropy(file_path):
    with open(file_path, "rb") as f:
        byte_counts = Counter(f.read())
        file_size = sum(byte_counts.values())
        entropy = -sum((count / file_size) * math.log2(count / file_size) for count in byte_counts.values())
        return entropy

def detect_encrypted_files():
    for root, _, files in os.walk("C:/"):
        for file in files:
            file_path = os.path.join(root, file)
            entropy = calculate_entropy(file_path)
            if entropy > 7.5:  # High entropy indicates encryption
                text_area.insert(tk.END, f"\n🔒 Encrypted File Detected: {file_path}\n")

# ✅ Network Intrusion Detection
def detect_intrusion(packet):
    if packet.haslayer("TCP") and packet["TCP"].flags == "S":
        text_area.insert(tk.END, f"\n🚨 Suspicious TCP SYN Packet Detected: {packet.summary()}\n")

def start_network_monitoring():
    sniff(prn=detect_intrusion, store=False)

# ✅ Auto-Block Suspicious IPs
def block_ip(ip):
    subprocess.run(f"netsh advfirewall firewall add rule name='Block {ip}' dir=in action=block remoteip={ip}", shell=True)
    text_area.insert(tk.END, f"\n🚫 Blocked IP: {ip}\n")

# ✅ Data Backup and Recovery
def backup_files(source, destination):
    shutil.copytree(source, destination)
    text_area.insert(tk.END, f"\n📂 Backup Completed: {source} -> {destination}\n")

# ✅ Dark Web Monitoring
def check_dark_web(email):
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
    response = requests.get(url)
    if response.status_code == 200:
        text_area.insert(tk.END, f"\n🌐 Dark Web Leak Detected for: {email}\n")

# ✅ System Log Analysis
def analyze_logs():
    logs = subprocess.getoutput("wevtutil qe System /f:text")
    if "Error" in logs:
        text_area.insert(tk.END, f"\n📜 Suspicious Log Entry:\n{logs}\n")

# ✅ Auto-Update Feature
def check_for_updates():
    response = requests.get("https://api.yourserver.com/version")
    if response.text != CURRENT_VERSION:
        text_area.insert(tk.END, f"\n🔄 Update Available: {response.text}\n")

# ✅ Two-Factor Authentication (2FA)
def verify_2fa(code):
    totp = pyotp.TOTP("base32secret3232")
    if totp.verify(code):
        text_area.insert(tk.END, "\n🔒 2FA Verified\n")
    else:
        text_area.insert(tk.END, "\n❌ 2FA Verification Failed\n")

# ✅ User Activity Monitoring
def monitor_user_activity():
    users = psutil.users()
    for user in users:
        text_area.insert(tk.END, f"\n👤 User Activity: {user.name} ({user.terminal})\n")

# ✅ Secure File Deletion
def secure_delete(file_path):
    with open(file_path, "wb") as f:
        f.write(random.randbytes(os.path.getsize(file_path)))
    os.remove(file_path)
    text_area.insert(tk.END, f"\n🗑️ Securely Deleted: {file_path}\n")

# ✅ Phishing Detection
def detect_phishing(url):
    response = requests.get(f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key=YOUR_API_KEY")
    if response.json().get("matches"):
        text_area.insert(tk.END, f"\n🎣 Phishing Detected: {url}\n")

# ✅ GUI Setup
root = ThemedTk(theme="black")
root.title("🔥 Advanced PC Security System")
root.geometry("1000x700")
root.configure(bg="black")

frame = ttk.Frame(root, padding=10)
frame.pack(fill="both", expand=True)

title_label = ttk.Label(frame, text="🔥 Advanced PC Security System", font=("Consolas", 18, "bold"), foreground="#00ff00")
title_label.pack(pady=10)

text_area = scrolledtext.ScrolledText(frame, width=100, height=20, bg="black", fg="#00ff00", insertbackground="#00ff00", font=("Consolas", 12))
text_area.pack(pady=10)

status_label = ttk.Label(frame, text="System Monitoring Active...", font=("Consolas", 12), foreground="#00ff00")
status_label.pack(pady=5)

# Buttons for New Features
btn_firewall = ttk.Button(frame, text="🔥 Check Firewall", command=check_firewall, bootstyle="danger")
btn_firewall.pack(pady=5)

btn_ransomware = ttk.Button(frame, text="🛡️ Start Ransomware Protection", command=start_ransomware_protection, bootstyle="warning")
btn_ransomware.pack(pady=5)

btn_network = ttk.Button(frame, text="🌐 Start Network Monitoring", command=start_network_monitoring, bootstyle="primary")
btn_network.pack(pady=5)

btn_backup = ttk.Button(frame, text="📂 Backup Files", command=lambda: backup_files("C:/Important", "D:/Backup"), bootstyle="success")
btn_backup.pack(pady=5)

# ✅ Run Background Monitoring
threading.Thread(target=usb_monitor, daemon=True).start()
threading.Thread(target=resource_monitor, daemon=True).start()
threading.Thread(target=real_time_malware_detection, daemon=True).start()

root.mainloop()