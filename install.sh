#!/bin/bash
set -e

echo "[+] Installing SSH Honeypot..."

# Update system
sudo apt update

# Install system dependencies
sudo apt install -y python3 python3-pip

# Install Python dependencies
sudo pip3 install --upgrade pip
sudo pip3 install paramiko

# Create dedicated user (if not exists)
if ! id "honeypot" &>/dev/null; then
    sudo useradd -r -s /bin/false -M -d /opt/ssh-honeypot honeypot
    echo "[+] Created dedicated 'honeypot' user"
else
    echo "[+] 'honeypot' user already exists"
fi

# Create directories
sudo mkdir -p /opt/ssh-honeypot/logs

# Copy honeypot files
sudo cp honeypot.py /opt/ssh-honeypot/
sudo cp requirements.txt LICENSE README.md /opt/ssh-honeypot/

# Set permissions for dedicated user
sudo chown -R honeypot:honeypot /opt/ssh-honeypot
sudo chmod 755 /opt/ssh-honeypot
sudo chmod 755 /opt/ssh-honeypot/honeypot.py
sudo chmod 755 /opt/ssh-honeypot/logs
# SSH host key needs to be readable
sudo chmod 600 /opt/ssh-honeypot/ssh_host_rsa_key 2>/dev/null || true

# Copy systemd service
sudo cp ssh-honeypot.service /etc/systemd/system/

# Reload systemd
sudo systemctl daemon-reload

# Enable and start service
sudo systemctl enable ssh-honeypot
sudo systemctl restart ssh-honeypot

# Verify it's running
echo "[+] Checking service status..."
sleep 3
if sudo systemctl is-active --quiet ssh-honeypot; then
    echo "[✓] SSH Honeypot is running on port 2222"
else
    echo "[!] Service failed to start. Checking logs..."
    sudo journalctl -u ssh-honeypot -n 20 --no-pager
    exit 1
fi

echo ""
echo "[+] Installation complete!"
echo "[+] Logs: /opt/ssh-honeypot/logs/sessions.json"
echo "[+] Service: sudo systemctl status ssh-honeypot"
echo "[+] Test: ssh -p 2222 test@localhost"
echo "[+] View logs: sudo journalctl -u ssh-honeypot -f"