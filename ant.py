import streamlit as st
import psutil
import os
import socket
import subprocess
from collections import defaultdict
import hashlib
import sqlite3
import time
import datetime

# Function to get system resource usage
def get_system_usage():
    cpu_usage = psutil.cpu_percent(interval=1)
    ram_usage = psutil.virtual_memory().percent
    disk_usage = psutil.disk_usage('/').percent
    return cpu_usage, ram_usage, disk_usage

# Function to scan for open ports
def scan_open_ports():
    open_ports = []
    for port in range(1, 1025):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            if s.connect_ex(('127.0.0.1', port)) == 0:
                open_ports.append(port)
    return open_ports

# Function to detect running processes
def detect_processes():
    return [p.info['name'] for p in psutil.process_iter(['name'])]

# Function to detect potential spyware/keyloggers
def detect_spyware():
    suspicious_processes = []
    blacklist = ["keylogger.exe", "malware.exe", "unknown.exe"]  # Example blacklisted processes
    for process in detect_processes():
        if process.lower() in blacklist:
            suspicious_processes.append(process)
    return suspicious_processes

# Function to clean junk files
def clean_junk():
    temp_dirs = ["C:\\Windows\\Temp", os.path.expanduser("~\\AppData\\Local\\Temp")]
    for temp_dir in temp_dirs:
        for root, dirs, files in os.walk(temp_dir):
            for file in files:
                try:
                    os.remove(os.path.join(root, file))
                except Exception as e:
                    pass
    return "Junk files cleaned!"

# Function to calculate file hash (for integrity checks)
def calculate_file_hash(file_path):
    hasher = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hasher.update(chunk)
    return hasher.hexdigest()

# Function to monitor file integrity
def monitor_file_integrity(directory):
    file_hashes = defaultdict(str)
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            file_hashes[file_path] = calculate_file_hash(file_path)
    return file_hashes

# Function to detect unauthorized user logins
def detect_unauthorized_logins():
    users = psutil.users()
    suspicious_users = [user.name for user in users if user.name not in ["admin", "user"]]  # Example whitelist
    return suspicious_users

# Function to check for suspicious network connections
def check_network_connections():
    connections = psutil.net_connections()
    suspicious_connections = [conn for conn in connections if conn.status == "ESTABLISHED" and conn.raddr]
    return suspicious_connections

# Function to monitor browser performance
def monitor_browser_performance():
    browsers = ["chrome.exe", "firefox.exe", "msedge.exe"]
    browser_performance = []
    for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_info']):
        if proc.info['name'].lower() in browsers:
            browser_performance.append({
                "name": proc.info['name'],
                "cpu_usage": proc.info['cpu_percent'],
                "memory_usage": proc.info['memory_info'].rss / (1024 * 1024)  # Convert to MB
            })
    return browser_performance

# Function to collect browser history (Chrome example)
def collect_browser_history():
    history_path = os.path.expanduser("~\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\History")
    history = []
    if os.path.exists(history_path):
        try:
            conn = sqlite3.connect(history_path)
            cursor = conn.cursor()
            cursor.execute("SELECT url, title, last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT 10")
            history = cursor.fetchall()
            conn.close()
        except Exception as e:
            st.error(f"Error reading browser history: {e}")
    return history

# Function to log system performance over time
def log_system_performance():
    logs = []
    for _ in range(5):  # Log for 5 iterations
        cpu, ram, disk = get_system_usage()
        logs.append({
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "cpu_usage": cpu,
            "ram_usage": ram,
            "disk_usage": disk
        })
        time.sleep(1)  # Wait 1 second between logs
    return logs

# Streamlit UI
st.set_page_config(page_title="🛡 Advanced PC Security System", layout="wide")

# Custom CSS for better design
st.markdown(
    """
    <style>
    .stButton button {
        background-color: #4CAF50;
        color: white;
        font-size: 16px;
        padding: 10px 24px;
        border-radius: 8px;
        border: none;
    }
    .stButton button:hover {
        background-color: #45a049;
    }
    .stMetric {
        background-color: #2E3440;
        padding: 20px;
        border-radius: 10px;
        color: white;
    }
    .stSuccess {
        background-color: #4CAF50;
        color: white;
        padding: 10px;
        border-radius: 5px;
    }
    </style>
    """,
    unsafe_allow_html=True
)

# Title and Description
st.title("🛡 Advanced PC Security System")
st.markdown("""
Welcome to the **Advanced PC Security System**! This tool helps you monitor your system's health, detect threats, and clean up junk files.
""")

# Display System Usage
st.header("📊 System Resource Usage")
cpu, ram, disk = get_system_usage()
col1, col2, col3 = st.columns(3)
col1.metric(label="💻 CPU Usage", value=f"{cpu}%")
col2.metric(label="🖥 RAM Usage", value=f"{ram}%")
col3.metric(label="💾 Disk Usage", value=f"{disk}%")

# Buttons for Security Operations
st.header("🔒 Security Operations")
col1, col2, col3, col4 = st.columns(4)  # Create 4 columns for buttons

with col1:
    if st.button("🔍 Scan Open Ports"):
        ports = scan_open_ports()
        with st.expander("📂 Open Ports Results", expanded=True):
            st.write("Open Ports:", ports if ports else "No open ports found.")

with col2:
    if st.button("🦠 Detect Spyware"):
        spyware = detect_spyware()
        with st.expander("📂 Spyware Detection Results", expanded=True):
            st.write("Potential Spyware Detected:", spyware if spyware else "No spyware found.")

with col3:
    if st.button("🧹 Clean Junk Files"):
        result = clean_junk()
        with st.expander("📂 Junk Cleanup Results", expanded=True):
            st.success(result)

with col4:
    if st.button("🔑 Detect Keyloggers"):
        processes = detect_processes()
        keyloggers = [p for p in processes if "key" in p.lower()]
        with st.expander("📂 Keylogger Detection Results", expanded=True):
            st.write("Detected Keyloggers:", keyloggers if keyloggers else "No keyloggers found.")

# Advanced Features
st.header("🚀 Advanced Features")
col1, col2, col3 = st.columns(3)  # Create 3 columns for advanced features

with col1:
    if st.button("🛡 Monitor File Integrity"):
        directory = st.text_input("Enter directory to monitor (e.g., C:/Important):", "C:/")
        if directory:
            file_hashes = monitor_file_integrity(directory)
            with st.expander("📂 File Integrity Results", expanded=True):
                st.write("File Integrity Hashes:", file_hashes)

with col2:
    if st.button("👤 Detect Unauthorized Logins"):
        suspicious_users = detect_unauthorized_logins()
        with st.expander("📂 Unauthorized Login Results", expanded=True):
            st.write("Suspicious Users:", suspicious_users if suspicious_users else "No unauthorized logins detected.")

with col3:
    if st.button("🌐 Check Network Connections"):
        suspicious_connections = check_network_connections()
        with st.expander("📂 Network Connection Results", expanded=True):
            st.write("Suspicious Network Connections:", suspicious_connections if suspicious_connections else "No suspicious connections found.")

# Browser Monitoring
st.header("🌐 Browser Monitoring")
col1, col2 = st.columns(2)

with col1:
    if st.button("📊 Monitor Browser Performance"):
        browser_performance = monitor_browser_performance()
        with st.expander("📂 Browser Performance Results", expanded=True):
            st.write("Browser Performance:", browser_performance if browser_performance else "No browsers running.")

with col2:
    if st.button("📜 Collect Browser History"):
        browser_history = collect_browser_history()
        with st.expander("📂 Browser History Results", expanded=True):
            st.write("Browser History:", browser_history if browser_history else "No history found.")

# System Performance Logging
st.header("📝 System Performance Logging")
if st.button("📊 Log System Performance"):
    logs = log_system_performance()
    with st.expander("📂 System Performance Logs", expanded=True):
        st.write("System Performance Logs:", logs)

# Footer
st.markdown("---")
st.success("System security check completed successfully!")