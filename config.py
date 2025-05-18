import os
import socket

# ==========================
# 🔹 NETWORK SECURITY SETTINGS
# ==========================

ALLOWED_IPS = ["127.0.0.1"]  # List of IPs allowed to access the system
CRITICAL_IPS = ["127.0.0.1"]  # Management IPs that should NEVER be blocked
CRITICAL_PORTS = ["14", "443"]  # Ports that should NEVER be blocked (SSH, HTTPS)

# ==========================
# 🔹 FAILSAFE & SAFE MODE
# ==========================

FAILSAFE_MODE = False  # When True, no block/unblock is allowed
SAFE_MODE = False      # Default is off (can be toggled dynamically)

# Log file for failsafe actions
FAILSAFE_LOG_PATH = "./logger/failsafe.log"

# Ensure the log directory exists
os.makedirs(os.path.dirname(FAILSAFE_LOG_PATH), exist_ok=True)

# ==========================
# 🔹 ADMIN OVERRIDE SECURITY
# ==========================

# ⚠️ It's a security risk to hardcode passwords in files. Use an environment variable instead!
ADMIN_OVERRIDE_PASSWORD = "adityatest"
# Make sure to set the environment variable in production using:
# export ADMIN_OVERRIDE_PASSWORD="YourSecurePassword"

# ==========================
# 🔹 DYNAMIC IP FETCHING
# ==========================

def get_local_ip():
    """Fetch the current machine's local IP address dynamically (without netifaces)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))  # Connect to a public server (Google DNS)
        local_ip = s.getsockname()[0]
        s.close()
        return f"{local_ip}/24"
    except Exception as e:
        print(f"Error fetching IP: {e}")
    return "192.168.1.101/24"  # Default fallback


# Dynamically set the current IP for testing
CURRENT_IP = get_local_ip()
