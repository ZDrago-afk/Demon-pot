<p align="center">
  <img src="../pictures/demon_pot_2.png" alt="Demon-Pot Logo" width="300">
</p>

# Demon-Pot (Paramiko-based SSH Honeypot)

An advanced SSH honeypot built with Python and Paramiko.  
It simulates a realistic Linux environment to capture attacker activity —  
credentials, commands, session behaviour, and attack patterns.

This project is intended for educational and security research purposes only.

---

## 🚀 Features

- Listens on a configurable SSH port (default: `2222`)
- Accepts **all** usernames and passwords — logs every attempt
- Logs public-key fingerprints (auth always denied)
- **Realistic fake Linux shell** with 35+ simulated commands
- Deep fake filesystem (`/etc`, `/home`, `/var/www`, `/proc`, and more)
- Fake sensitive files: `wp-config.php`, `config.yaml`, `/etc/shadow`, crontabs
- **Per-IP rate limiting** — blocks brute-force floods automatically
- **Three separate log streams**: sessions, credentials, commands
- Rotating file logs (10 MB per file, 5 backups)
- Live stats summary on graceful shutdown (Ctrl+C)
- Persistent RSA host key (no fingerprint change on restart)
- Idle session timeout — drops inactive connections
- Runs as a hardened `systemd` service under a dedicated user
- Configurable entirely via environment variables

---

## 📂 Project Structure

| File                  | Purpose                                      |
|-----------------------|----------------------------------------------|
| `honeypot.py`         | Main SSH honeypot script                     |
| `install.sh`          | Automated installation script                |
| `ssh-honeypot.service`| Systemd service unit file                    |
| `requirements.txt`    | Python dependencies                          |
| `README.md`           | Project overview (this file)                 |
| `OPERATION.md`        | Full operation, configuration & log analysis guide |

---

## 🛠️ Installation

> ⚠️ Run only on a VM or an isolated, dedicated research system.

```bash
git clone https://github.com/yourname/demon-pot
cd demon-pot
chmod +x install.sh
sudo ./install.sh
```

The installer creates a Python virtual environment, a dedicated `honeypot` system user, and registers the systemd service automatically.

---

## 🔧 Quick Configuration

All settings are controlled via environment variables:

| Variable            | Default | Description                              |
|---------------------|---------|------------------------------------------|
| `HONEYPOT_PORT`     | `2222`  | Listening port                           |
| `HONEYPOT_BIND`     | `0.0.0.0` | Bind address                           |
| `HONEYPOT_RATE`     | `10`    | Max auth attempts before rate-limit      |
| `HONEYPOT_WINDOW`   | `60`    | Rate-limit window in seconds             |
| `HONEYPOT_IDLE`     | `120`   | Idle timeout per session (seconds)       |

See **OPERATION.md** for full configuration details.

---

## 📜 Logs

All captured data is stored in `/opt/ssh-honeypot/logs/`:

| File                | Contents                                   |
|---------------------|--------------------------------------------|
| `sessions.jsonl`    | Full session records with all commands     |
| `credentials.jsonl` | Every username + password attempt          |
| `commands.jsonl`    | Every command with IP, session ID, timestamp|
| `honeypot.log`      | Human-readable runtime log (auto-rotating) |
| `stats.json`        | Aggregate stats (saved on clean shutdown)  |

### Quick log preview

```bash
# Live credential feed
tail -f /opt/ssh-honeypot/logs/credentials.jsonl | python3 -m json.tool

# Top passwords attempted
cat /opt/ssh-honeypot/logs/credentials.jsonl \
  | python3 -c "
import sys,json
from collections import Counter
c=Counter(json.loads(l)['password'] for l in sys.stdin if l.strip())
[print(f'{n:>5}  {p}') for p,n in c.most_common(10)]
"
```

---

## 🖥️ Managing the Service

```bash
sudo systemctl status  ssh-honeypot   # Check status
sudo systemctl restart ssh-honeypot   # Restart
sudo journalctl -u ssh-honeypot -f    # Live log stream
```

---

## 🔬 Simulated Commands

The fake shell responds to: `ls`, `cd`, `cat`, `pwd`, `whoami`, `id`, `uname`,
`hostname`, `ps`, `ps aux`, `ifconfig`, `ip`, `netstat`, `ss`, `df`, `free`,
`uptime`, `w`, `date`, `history`, `env`, `echo`, `sudo`, `su`, `wget`, `curl`,
`python3`, `which`, `find`, `touch`, `mkdir`, `rm`, `chmod`, `crontab`,
`nano`, `vim`, `clear`, `exit`, and more.

---

## ⚠️ Disclaimer

This project is for **educational and security research purposes only**.  
Do **NOT** deploy on production systems or expose to sensitive networks.  
The author is not responsible for any misuse of this software.

---

## 📄 License

MIT License — see `LICENSE` for details.
