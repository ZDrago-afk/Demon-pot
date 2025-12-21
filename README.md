# SSH Honeypot (Paramiko-based)

A simple SSH honeypot built using Python and Paramiko.  
It simulates a fake Linux environment to capture attacker activity such as
login credentials and executed commands.

This project is intended for educational and research purposes only.

---

## 🚀 Features
- Listens on a custom SSH port (default: 2222)
- Accepts all usernames and passwords
- Logs attacker IP, credentials, and commands
- Simulated Linux shell
- Persistent SSH host key
- Runs as a systemd service

---

## 📂 Project Structure

ssh-honeypot/
├── honeypot.py
├── install.sh
├── ssh-honeypot.service
├── requirements.txt
├── README.md
├── LICENSE
└── .gitignore

---

## 🛠️ Installation

⚠️ Run on a VM or isolated system only.

chmod +x install.sh
sudo ./install.sh

---

## 📜 Logs

All captured sessions are stored in:
/opt/ssh-honeypot/logs/sessions.json

---

## ⚠️ Disclaimer

This project is for educational and research purposes only.
Do NOT deploy on production systems or expose to sensitive networks.

The author is not responsible for misuse of this software.
