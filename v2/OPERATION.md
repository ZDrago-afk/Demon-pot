# Demon-Pot — Operation Guide

> ⚠️ **Run only on isolated VMs or dedicated research systems. Never on production infrastructure.**

---

## Table of Contents

1. [Installation](#installation)
2. [Configuration](#configuration)
3. [Running & Managing the Service](#running--managing-the-service)
4. [Log Files](#log-files)
5. [Reading & Analyzing Logs](#reading--analyzing-logs)
6. [Environment Variables](#environment-variables)
7. [Firewall Setup](#firewall-setup)
8. [Uninstallation](#uninstallation)
9. [Troubleshooting](#troubleshooting)

---

## Installation

### Prerequisites

| Requirement | Version |
|-------------|---------|
| OS          | Ubuntu 20.04+ / Debian 11+ |
| Python      | 3.8+ |
| RAM         | 256 MB minimum |
| Disk        | 1 GB for logs |

### Quick Install

```bash
git clone https://github.com/yourname/demon-pot
cd demon-pot
chmod +x install.sh
sudo ./install.sh
```

The installer will:
- Create a dedicated `honeypot` system user
- Install dependencies into a Python virtual environment at `/opt/ssh-honeypot/venv/`
- Register and start the `ssh-honeypot` systemd service

---

## Configuration

All settings can be overridden via **environment variables** (set them in the systemd service or your shell):

| Variable              | Default              | Description                              |
|-----------------------|----------------------|------------------------------------------|
| `HONEYPOT_PORT`       | `2222`               | Port to listen on                        |
| `HONEYPOT_BIND`       | `0.0.0.0`            | Bind address                             |
| `HONEYPOT_BASE_DIR`   | `/opt/ssh-honeypot`  | Root directory for keys and logs         |
| `HONEYPOT_MAX_CON`    | `100`                | Max queued connections                   |
| `HONEYPOT_RATE`       | `10`                 | Auth attempts before IP is rate-limited  |
| `HONEYPOT_WINDOW`     | `60`                 | Rate-limit time window (seconds)         |
| `HONEYPOT_IDLE`       | `120`                | Idle session timeout (seconds)           |

### Changing the Port

Edit `/etc/systemd/system/ssh-honeypot.service`, add to `[Service]`:

```ini
Environment="HONEYPOT_PORT=22"
```

Then reload:

```bash
sudo systemctl daemon-reload
sudo systemctl restart ssh-honeypot
```

> **Note:** Binding to port 22 requires either running as root (not recommended) or using `authbind` / `CAP_NET_BIND_SERVICE`.

### Granting Low-Port Access (optional)

```bash
sudo setcap 'cap_net_bind_service=+ep' /opt/ssh-honeypot/venv/bin/python3
```

---

## Running & Managing the Service

```bash
# Start
sudo systemctl start ssh-honeypot

# Stop
sudo systemctl stop ssh-honeypot

# Restart
sudo systemctl restart ssh-honeypot

# Enable auto-start on boot
sudo systemctl enable ssh-honeypot

# Disable auto-start
sudo systemctl disable ssh-honeypot

# Check status
sudo systemctl status ssh-honeypot

# Live service log (press Ctrl+C to exit)
sudo journalctl -u ssh-honeypot -f

# Last 50 lines
sudo journalctl -u ssh-honeypot -n 50 --no-pager
```

### Running Manually (for testing)

```bash
cd /opt/ssh-honeypot
sudo -u honeypot venv/bin/python3 honeypot.py --port 2222

# Custom bind and port
sudo -u honeypot venv/bin/python3 honeypot.py --port 2222 --bind 0.0.0.0
```

### Test the Honeypot

```bash
ssh -p 2222 admin@localhost
# Enter any password — it will be accepted and logged
```

---

## Log Files

All logs are stored in `/opt/ssh-honeypot/logs/`:

| File                | Format  | Contents                                         |
|---------------------|---------|--------------------------------------------------|
| `sessions.jsonl`    | JSONL   | Full session records (start, end, all commands)  |
| `credentials.jsonl` | JSONL   | Every auth attempt (username + password)         |
| `commands.jsonl`    | JSONL   | Every command with session ID, IP, timestamp     |
| `honeypot.log`      | Text    | Human-readable runtime log (rotates at 10 MB)   |
| `stats.json`        | JSON    | Cumulative statistics (saved on graceful exit)  |

---

## Reading & Analyzing Logs

### View Recent Credentials (last 20)

```bash
tail -n 20 /opt/ssh-honeypot/logs/credentials.jsonl | python3 -m json.tool
```

### Top 10 Passwords Tried

```bash
cat /opt/ssh-honeypot/logs/credentials.jsonl \
  | python3 -c "
import sys, json
from collections import Counter
c = Counter()
for line in sys.stdin:
    try: c[json.loads(line)['password']] += 1
    except: pass
for pw, n in c.most_common(10):
    print(f'{n:>6}  {pw}')
"
```

### Top 10 Usernames Tried

```bash
cat /opt/ssh-honeypot/logs/credentials.jsonl \
  | python3 -c "
import sys, json
from collections import Counter
c = Counter()
for line in sys.stdin:
    try: c[json.loads(line)['username']] += 1
    except: pass
for u, n in c.most_common(10):
    print(f'{n:>6}  {u}')
"
```

### Commands Run by Attackers

```bash
cat /opt/ssh-honeypot/logs/commands.jsonl \
  | python3 -c "
import sys, json
for line in sys.stdin:
    try:
        d = json.loads(line)
        print(f\"[{d['timestamp'][:19]}] {d['ip']:<16} {d['username']:<12} {d['command']}\")
    except: pass
" | tail -50
```

### Sessions by IP

```bash
cat /opt/ssh-honeypot/logs/sessions.jsonl \
  | python3 -c "
import sys, json
from collections import Counter
c = Counter()
for line in sys.stdin:
    try: c[json.loads(line)['ip']] += 1
    except: pass
for ip, n in c.most_common(20):
    print(f'{n:>6}  {ip}')
"
```

### View Stats Summary

```bash
cat /opt/ssh-honeypot/logs/stats.json | python3 -m json.tool
```

---

## Environment Variables

To permanently set variables, edit the service file:

```bash
sudo systemctl edit ssh-honeypot
```

Add:

```ini
[Service]
Environment="HONEYPOT_PORT=2222"
Environment="HONEYPOT_RATE=5"
Environment="HONEYPOT_WINDOW=30"
```

---

## Firewall Setup

Expose only the honeypot port. Block all other inbound traffic:

```bash
# Allow honeypot port
sudo ufw allow 2222/tcp comment "SSH Honeypot"

# Allow your real SSH on a different port (important!)
sudo ufw allow 22222/tcp comment "Real SSH"

# Enable firewall
sudo ufw enable
sudo ufw status
```

> **Important:** Move your real SSH to a non-standard port **before** enabling the honeypot on port 22 or 2222, so you don't lose access to your machine.

---

## Uninstallation

```bash
sudo systemctl stop ssh-honeypot
sudo systemctl disable ssh-honeypot
sudo rm /etc/systemd/system/ssh-honeypot.service
sudo systemctl daemon-reload
sudo rm -rf /opt/ssh-honeypot
sudo userdel honeypot
```

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| `Address already in use` | Another process is on port 2222. Check with `ss -tlnp \| grep 2222` |
| `Permission denied` on port 22 | Use `authbind` or `setcap` (see Configuration section) |
| Service starts but no logs appear | Check ownership: `sudo chown -R honeypot:honeypot /opt/ssh-honeypot/logs` |
| `paramiko` import error | Re-run: `sudo /opt/ssh-honeypot/venv/bin/pip install paramiko` |
| Key regenerated every restart | Ensure `/opt/ssh-honeypot/` is writable by the `honeypot` user |
| High CPU usage | Many concurrent bots — reduce `HONEYPOT_IDLE` and `HONEYPOT_RATE` |

### Check What's Running on the Port

```bash
ss -tlnp | grep 2222
```

### Verify the Host Key Exists

```bash
ls -la /opt/ssh-honeypot/ssh_host_rsa_key
```

### Watch Live Connections

```bash
sudo journalctl -u ssh-honeypot -f | grep -E "AUTH|SESSION|ENDED"
```

---

*Demon-Pot is for educational and security research purposes only.*
