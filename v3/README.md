<p align="center">
  <img src="../pictures/demon_pot.png" alt="Demon-Pot Logo" width="300">
</p>

<h1 align="center">Demon-Pot</h1>
<p align="center">
  <b>Advanced SSH Honeypot &amp; Threat Intelligence Sensor</b><br>
  <sub>Paramiko · Docker · AbuseIPDB · GreyNoise · ELK Stack</sub>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.11-blue?logo=python" alt="Python 3.11">
  <img src="https://img.shields.io/badge/docker-ready-2496ED?logo=docker" alt="Docker">
  <img src="https://img.shields.io/badge/license-MIT-green" alt="MIT License">
  <img src="https://img.shields.io/badge/purpose-research%20only-red" alt="Research Only">
</p>

---

> ⚠️ **For educational and security research use only.**
> Deploy exclusively on isolated VMs or dedicated cloud instances in a DMZ.
> Never on production systems.

---

## What Is Demon-Pot?

Demon-Pot is a production-grade SSH honeypot that masquerades as a real Ubuntu server. It captures attacker credentials, records every command they run, and enriches each attacker IP with live threat intelligence — all without exposing your real infrastructure.

**What attackers see:** A fully responsive Ubuntu 22.04 shell with 35+ working commands, a realistic filesystem, fake sensitive files (`wp-config.php`, database configs, crontabs), and a convincing MOTD.

**What you get:** Structured JSON logs, real-time threat intel scores, geographic data, ISP classification, and optional automated IP blocking.

---

## Architecture

```
Internet
    │
    ▼ port 22 (redirected via iptables NAT)
┌─────────────────────────────────────────────┐
│              Docker Stack                    │
│                                              │
│  ┌──────────────┐   shared   ┌───────────┐  │
│  │  honeypot    │── volume ──│  filebeat │──┼──► Elasticsearch / Kibana
│  │  (Alpine)    │   /logs    └───────────┘  │
│  └──────┬───────┘                           │
│         │ /logs (read-only)   ┌───────────┐ │
│         └────────────────────►│  threat-  │ │
│                               │  intel    │─┼──► AbuseIPDB / GreyNoise
│                               └───────────┘ │
└─────────────────────────────────────────────┘
    │
    ▼ port 50022 (your real SSH, hidden)
  Your admin shell
```

---

## Features

| Feature | Details |
|---------|---------|
| **Realistic SSH shell** | 35+ commands, full fake filesystem, fake sensitive files |
| **Per-IP rate limiting** | Auto-drops flood IPs after configurable threshold |
| **Public-key logging** | Records key fingerprints even when auth is denied |
| **Separate log streams** | `sessions.jsonl`, `credentials.jsonl`, `commands.jsonl` |
| **Rotating logs** | 10 MB per file, 5 backups |
| **Threat Intel sidecar** | AbuseIPDB score, GreyNoise classification, ISP, country |
| **Auto-block** | Optional iptables drop rule for high-score IPs |
| **Port disguise** | iptables NAT redirects port 22 → honeypot on 2222 |
| **Centralized logging** | Filebeat ships all streams to ELK with daily indices |
| **Docker deployment** | Multi-stage Alpine build, read-only filesystem, non-root |
| **Systemd fallback** | Works without Docker on bare Ubuntu/Debian |
| **Config via env vars** | No source edits required |
| **Stats on shutdown** | Top IPs, usernames, passwords, commands on Ctrl+C |

---

## Project Structure

```
demon-pot/
├── honeypot.py              # Core SSH honeypot server
├── threat_intel.py          # Threat intelligence sidecar
├── Dockerfile               # Multi-stage Alpine build (honeypot)
├── Dockerfile.sidecar       # Alpine build (threat-intel service)
├── docker-compose.yml       # Full stack orchestration
├── .env.example             # All configuration variables
├── setup_port_forward.sh    # iptables port 22 → 2222 redirect
├── install.sh               # Bare-metal systemd installer
├── ssh-honeypot.service     # Hardened systemd unit
├── requirements.txt         # Python dependencies
├── filebeat/
│   ├── filebeat.yml         # Filebeat → Elasticsearch config
│   └── ilm_policy.json      # Index lifecycle (hot → warm → delete 90d)
├── README.md                # This file
└── OPERATION.md             # Full operation & log analysis guide
```

---

## Quick Start (Docker — Recommended)

```bash
# 1. Clone and configure
git clone https://github.com/yourname/demon-pot
cd demon-pot
cp .env.example .env
# Edit .env — add your AbuseIPDB / GreyNoise API keys

# 2. Build and start the full stack
docker compose up -d --build

# 3. Verify it is running
docker compose ps
docker compose logs -f honeypot

# 4. Test from your local machine
ssh -p 2222 root@<your-server-ip>
# Enter any password — it is accepted and logged
```

---

## Quick Start (Bare Metal / systemd)

```bash
chmod +x install.sh
sudo ./install.sh

# Check status
sudo systemctl status ssh-honeypot
sudo journalctl -u ssh-honeypot -f
```

---

## Port Disguise — Capture Real Port 22 Traffic

Automated botnets scan port 22. Running only on 2222 misses the bulk of real-world attack traffic. Fix this in one step:

```bash
chmod +x setup_port_forward.sh
sudo ./setup_port_forward.sh
# Moves your real SSH to port 50022
# Silently redirects external port 22 → honeypot on 2222
```

To undo:

```bash
sudo ./setup_port_forward.sh --undo
```

---

## Threat Intelligence

The `threat_intel.py` sidecar watches `credentials.jsonl` in real-time. For each new attacker IP it queries AbuseIPDB (abuse confidence score, ISP, country, prior reports) and GreyNoise (scanner classification). Output is colour-coded by risk level:

```
────────────────────────────────────────────────────────────
  IP         : 185.220.101.45   [HIGH RISK]
  Creds      : root:123456
  Country    : DE   ISP: Tor-Exit-Node GmbH
  AbuseScore : 98/100  Reports: 1,243
  GreyNoise  : malicious — TOR Exit Node
────────────────────────────────────────────────────────────
```

Enable auto-blocking via `.env`:

```bash
AUTO_BLOCK=true
BLOCK_THRESHOLD=80
```

---

## Log Files

| File | Contents |
|------|----------|
| `sessions.jsonl` | Full sessions with every command |
| `credentials.jsonl` | Every username + password attempt |
| `commands.jsonl` | Per-command records with session ID |
| `honeypot.log` | Human-readable runtime log (rotating) |
| `stats.json` | Aggregate stats saved on clean shutdown |
| `intel_output/enriched.jsonl` | Threat-intel-enriched attacker records |
| `intel_output/blocked_ips.jsonl` | IPs that triggered auto-block |

---

## Configuration Reference

| Variable | Default | Description |
|----------|---------|-------------|
| `HONEYPOT_PORT` | `2222` | Honeypot listen port |
| `HONEYPOT_RATE` | `10` | Auth attempts before rate-limit |
| `HONEYPOT_WINDOW` | `60` | Rate-limit window (seconds) |
| `HONEYPOT_IDLE` | `120` | Idle session timeout (seconds) |
| `ABUSEIPDB_KEY` | — | AbuseIPDB v2 API key |
| `GREYNOISE_KEY` | — | GreyNoise API key (optional) |
| `AUTO_BLOCK` | `false` | Enable iptables auto-block |
| `BLOCK_THRESHOLD` | `80` | AbuseIPDB score to trigger block |
| `ELASTICSEARCH_HOST` | — | ELK ingest endpoint |

Full details in **OPERATION.md**.

---

## Simulated Shell Commands

`ls · cd · cat · pwd · whoami · id · hostname · uname · date · uptime · w · ps · ps aux · ifconfig · ip · netstat · ss · df · free · history · env · echo · sudo · su · wget · curl · python3 · which · find · touch · mkdir · rm · chmod · crontab · nano · vim · clear · exit`

---

## Disclaimer

This project is for **educational and security research purposes only.**
The author is not responsible for any misuse.
Do not deploy on production systems or networks containing sensitive data.

---

## License

MIT — see `LICENSE` for details.
