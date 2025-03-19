import os
import subprocess
import tkinter as tk
from tkinter import scrolledtext
import psutil
import threading
import time
from PIL import ImageGrab
import telegram
from ttkthemes import ThemedTk
import ttkbootstrap as ttk

# ✅ Telegram Alert Setup
BOT_TOKEN = "https://api.telegram.org/bot123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11/getMe"
CHAT_ID = "5985821200"

def send_alert(message, screenshot=False):
    bot = telegram.Bot(token=BOT_TOKEN)
    bot.send_message(chat_id=CHAT_ID, text=message)
    if screenshot:
        image = ImageGrab.grab()
        image.save("screenshot.jpg")
        bot.send_photo(chat_id=CHAT_ID, photo=open("screenshot.jpg", "rb"))

def scan_ports():
    result = subprocess.getoutput("netstat -ano")
    text_area.insert(tk.END, f"\n🔍 Open Ports:\n{result}\n")

def detect_spyware():
    processes = subprocess.getoutput("tasklist")
    spyware_apps = ["zoom.exe", "teams.exe", "anydesk.exe"]
    for app in spyware_apps:
        if app in processes:
            text_area.insert(tk.END, f"\n⚠ Spyware Detected: {app}\n")
            send_alert(f"⚠ Spyware Detected: {app}")

def usb_monitor():
    prev_usb = set(psutil.disk_partitions())
    while True:
        current_usb = set(psutil.disk_partitions())
        new_usb = current_usb - prev_usb
        if new_usb:
            text_area.insert(tk.END, f"\n🚨 Unauthorized USB Detected!\n")
        time.sleep(5)

def ai_virus_scanner():
    suspicious_files = [".exe", ".bat", ".vbs", ".dll"]
    virus_paths = ["C:/Users", "C:/Windows/System32"]
    for path in virus_paths:
        for root, dirs, files in os.walk(path):
            for file in files:
                if any(file.endswith(ext) for ext in suspicious_files):
                    text_area.insert(tk.END, f"\n🦠 Suspicious File: {file}\n")
                    send_alert(f"🦠 Virus Detected: {file}")

def keylogger_detector():
    keyloggers = ["keylogger.exe", "hook.dll", "logger.py"]
    processes = subprocess.getoutput("tasklist")
    for keylogger in keyloggers:
        if keylogger in processes:
            text_area.insert(tk.END, f"\n⚠ Keylogger Detected: {keylogger}\n")
            send_alert(f"⚠ Keylogger Detected: {keylogger}")
            os.system(f"taskkill /IM {keylogger} /F")

def resource_monitor():
    while True:
        cpu = psutil.cpu_percent()
        ram = psutil.virtual_memory().percent
        disk = psutil.disk_usage('/').percent
        status_label.config(text=f"🔥 CPU: {cpu}%  |  RAM: {ram}%  |  DISK: {disk}%")
        time.sleep(2)

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

# ✅ Button Frame (Right to Left Alignment)
btn_frame = ttk.Frame(frame)
btn_frame.pack(pady=10, anchor="e")

btn_keylogger = ttk.Button(btn_frame, text="⚠ Detect Keyloggers", command=keylogger_detector, bootstyle="danger")
btn_keylogger.pack(side="center", padx=5)

btn_spyware = ttk.Button(btn_frame, text="🕵 Detect Spyware", command=detect_spyware, bootstyle="warning")
btn_spyware.pack(side="right", padx=5)

btn_ports = ttk.Button(btn_frame, text="🔌 Scan Open Ports", command=scan_ports, bootstyle="primary")
btn_ports.pack(side="right", padx=5)

btn_scan = ttk.Button(btn_frame, text="🦠 Scan for Virus", command=ai_virus_scanner, bootstyle="danger")
btn_scan.pack(side="right", padx=5)

# ✅ Run Background Monitoring
threading.Thread(target=usb_monitor, daemon=True).start()
threading.Thread(target=resource_monitor, daemon=True).start()

root.mainloop()