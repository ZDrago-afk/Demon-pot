#!/usr/bin/env python3
"""
Demon-Pot — Advanced Paramiko SSH Honeypot
Educational and research purposes only.
"""

import socket
import threading
import json
import os
import sys
import time
import signal
import logging
import argparse
import ipaddress
from collections import defaultdict
from datetime import datetime
from logging.handlers import RotatingFileHandler

try:
    import paramiko
except ImportError:
    print("Error: paramiko not installed. Run: pip install paramiko")
    sys.exit(1)

# ─────────────────────────── CONFIGURATION ───────────────────────────────────

CONFIG = {
    "port":             int(os.getenv("HONEYPOT_PORT",    "2222")),
    "bind":             os.getenv("HONEYPOT_BIND",        "0.0.0.0"),
    "base_dir":         os.getenv("HONEYPOT_BASE_DIR",    "/opt/ssh-honeypot"),
    "max_connections":  int(os.getenv("HONEYPOT_MAX_CON", "100")),
    # Rate-limit: block an IP after this many auth attempts within the window
    "rate_limit":       int(os.getenv("HONEYPOT_RATE",    "10")),
    "rate_window":      int(os.getenv("HONEYPOT_WINDOW",  "60")),   # seconds
    # Connection timeout (seconds of inactivity before dropping)
    "idle_timeout":     int(os.getenv("HONEYPOT_IDLE",    "120")),
    "server_version":   "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6",
    "motd": """\
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-91-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of {now}

  System load:  0.08               Processes:             142
  Usage of /:   34.2% of 19.52GB   Users logged in:       0
  Memory usage: 22%                IPv4 address for eth0: 10.0.2.15
  Swap usage:   0%

Last login: {last} from 192.168.0.1
""",
}

LOG_DIR     = os.path.join(CONFIG["base_dir"], "logs")
KEY_PATH    = os.path.join(CONFIG["base_dir"], "ssh_host_rsa_key")
SESSION_LOG = os.path.join(LOG_DIR, "sessions.jsonl")
CRED_LOG    = os.path.join(LOG_DIR, "credentials.jsonl")
CMD_LOG     = os.path.join(LOG_DIR, "commands.jsonl")
STATS_FILE  = os.path.join(LOG_DIR, "stats.json")

# ─────────────────────────── FAKE FILESYSTEM ─────────────────────────────────

FAKE_FS = {
    "/": ["bin", "boot", "dev", "etc", "home", "lib", "lib64",
          "media", "mnt", "opt", "proc", "root", "run", "sbin",
          "srv", "sys", "tmp", "usr", "var"],
    "/bin":         ["bash", "cat", "chmod", "chown", "cp", "curl", "date",
                     "df", "echo", "grep", "hostname", "kill", "ls", "mkdir",
                     "mv", "nano", "netcat", "ps", "pwd", "rm", "sh",
                     "sleep", "tar", "touch", "uname", "wget", "which"],
    "/boot":        ["grub", "vmlinuz-5.15.0-91-generic",
                     "initrd.img-5.15.0-91-generic", "System.map"],
    "/dev":         ["null", "zero", "random", "urandom", "sda", "sda1",
                     "sda2", "tty", "tty0", "pts"],
    "/etc":         ["apt", "bash.bashrc", "crontab", "cron.d",
                     "environment", "fstab", "group", "hostname", "hosts",
                     "hosts.allow", "hosts.deny", "issue", "motd",
                     "network", "os-release", "passwd", "profile",
                     "protocols", "resolv.conf", "shadow", "shells",
                     "ssh", "ssl", "sudoers", "sysctl.conf", "timezone"],
    "/etc/ssh":     ["ssh_config", "sshd_config", "ssh_host_rsa_key",
                     "ssh_host_ecdsa_key", "authorized_keys"],
    "/home":        ["admin", "deploy", "git", "ubuntu", "user"],
    "/home/admin":  [".bash_history", ".bashrc", ".profile", ".ssh",
                     "backup.sh", "notes.txt"],
    "/home/ubuntu": [".bash_history", ".bashrc", ".profile", ".ssh"],
    "/home/user":   [".bash_history", ".bashrc", ".profile"],
    "/opt":         ["app", "monitoring"],
    "/opt/app":     ["config.yaml", "start.sh", "app.log"],
    "/proc":        ["1", "cpuinfo", "meminfo", "net", "version"],
    "/root":        [".bash_history", ".bashrc", ".profile", ".ssh",
                     ".vimrc", "dead.letter"],
    "/root/.ssh":   ["authorized_keys", "known_hosts"],
    "/tmp":         [],
    "/usr":         ["bin", "include", "lib", "local", "sbin", "share"],
    "/usr/bin":     ["awk", "base64", "curl", "diff", "env", "find",
                     "free", "gcc", "git", "id", "less", "make",
                     "nc", "nmap", "openssl", "perl", "php", "pip3",
                     "python3", "sed", "sort", "ssh", "sudo", "tail",
                     "top", "unzip", "vim", "w", "wc", "wget", "xargs"],
    "/usr/local":   ["bin", "lib", "share"],
    "/var":         ["backups", "cache", "lib", "log", "mail",
                     "run", "spool", "tmp", "www"],
    "/var/log":     ["auth.log", "daemon.log", "kern.log", "messages",
                     "syslog", "ufw.log"],
    "/var/www":     ["html"],
    "/var/www/html":["index.html", "index.php", "wp-config.php",
                     "wp-login.php", ".htaccess"],
}

FAKE_FILES = {
    "/etc/hostname":    "ubuntu\n",
    "/etc/issue":       "Ubuntu 22.04.3 LTS \\n \\l\n",
    "/etc/os-release":  ('NAME="Ubuntu"\nVERSION="22.04.3 LTS (Jammy Jellyfish)"\n'
                         'ID=ubuntu\nID_LIKE=debian\nPRETTY_NAME="Ubuntu 22.04.3 LTS"\n'
                         'VERSION_ID="22.04"\nHOME_URL="https://www.ubuntu.com/"\n'),
    "/etc/passwd":      (
        "root:x:0:0:root:/root:/bin/bash\n"
        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
        "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
        "sys:x:3:3:sys:/dev:/usr/sbin/nologin\n"
        "sync:x:4:65534:sync:/bin:/bin/sync\n"
        "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
        "ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash\n"
        "admin:x:1001:1001:Admin:/home/admin:/bin/bash\n"
        "deploy:x:1002:1002:Deploy:/home/deploy:/bin/bash\n"
        "git:x:1003:1003:Git:/home/git:/usr/bin/git-shell\n"
    ),
    "/etc/shadow":      (
        "root:$6$rounds=5000$abc123$longhashhere:19000:0:99999:7:::\n"
        "ubuntu:$6$rounds=5000$xyz789$longhashhere2:19000:0:99999:7:::\n"
        "admin:$6$rounds=5000$def456$longhashhere3:19000:0:99999:7:::\n"
    ),
    "/etc/hosts":       (
        "127.0.0.1   localhost\n"
        "127.0.1.1   ubuntu\n"
        "::1         localhost ip6-localhost ip6-loopback\n"
        "ff02::1     ip6-allnodes\n"
        "ff02::2     ip6-allrouters\n"
    ),
    "/etc/resolv.conf": "nameserver 8.8.8.8\nnameserver 8.8.4.4\n",
    "/etc/crontab":     (
        "# /etc/crontab: system-wide crontab\n"
        "SHELL=/bin/sh\nPATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin\n\n"
        "17 * * * * root    cd / && run-parts --report /etc/cron.hourly\n"
        "25 6 * * * root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )\n"
        "47 6 * * 7 root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )\n"
    ),
    "/proc/version":    ("Linux version 5.15.0-91-generic (buildd@lcy02-amd64-007) "
                         "(gcc (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0, GNU ld (GNU Binutils "
                         "for Ubuntu) 2.38) #101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023\n"),
    "/proc/cpuinfo":    (
        "processor\t: 0\nvendor_id\t: GenuineIntel\n"
        "cpu family\t: 6\nmodel\t\t: 142\nmodel name\t: Intel(R) Core(TM) i7-10750H CPU @ 2.60GHz\n"
        "stepping\t: 12\nmicrocode\t: 0xf0\ncpu MHz\t\t: 2592.000\ncache size\t: 12288 KB\n"
        "cpu cores\t: 2\nbogomips\t: 5184.00\nflags\t\t: fpu vme de pse tsc msr pae mce\n\n"
        "processor\t: 1\nvendor_id\t: GenuineIntel\n"
        "cpu family\t: 6\nmodel\t\t: 142\nmodel name\t: Intel(R) Core(TM) i7-10750H CPU @ 2.60GHz\n"
        "stepping\t: 12\nmicrocode\t: 0xf0\ncpu MHz\t\t: 2592.000\ncache size\t: 12288 KB\n"
        "cpu cores\t: 2\nbogomips\t: 5184.00\nflags\t\t: fpu vme de pse tsc msr pae mce\n"
    ),
    "/proc/meminfo":    (
        "MemTotal:        2041344 kB\nMemFree:         1524208 kB\n"
        "MemAvailable:    1687940 kB\nBuffers:           48428 kB\n"
        "Cached:          269164 kB\nSwapCached:            0 kB\n"
        "SwapTotal:       2097148 kB\nSwapFree:        2097148 kB\n"
    ),
    "/home/admin/notes.txt": (
        "TODO:\n"
        "- Rotate AWS keys (deadline next Friday)\n"
        "- Update prod DB password\n"
        "- Check if backup script is working\n"
        "- Renew SSL cert expiring 2024-03-15\n\n"
        "Server IPs:\n"
        "prod-web:  10.0.1.5\n"
        "prod-db:   10.0.1.10\n"
        "staging:   10.0.2.5\n"
    ),
    "/opt/app/config.yaml": (
        "app:\n"
        "  name: myapp\n"
        "  env: production\n"
        "  port: 8080\n\n"
        "database:\n"
        "  host: 10.0.1.10\n"
        "  port: 5432\n"
        "  name: appdb\n"
        "  user: appuser\n"
        "  password: Str0ng@Pass2024!\n\n"
        "redis:\n"
        "  host: 10.0.1.15\n"
        "  port: 6379\n"
        "  password: redis_secret_9182\n"
    ),
    "/var/www/html/wp-config.php": (
        "<?php\n"
        "define( 'DB_NAME', 'wordpress' );\n"
        "define( 'DB_USER', 'wpuser' );\n"
        "define( 'DB_PASSWORD', 'wp@secure!2024' );\n"
        "define( 'DB_HOST', 'localhost' );\n"
        "define( 'DB_CHARSET', 'utf8' );\n"
        "?>\n"
    ),
}

# ─────────────────────────── GLOBAL STATE ────────────────────────────────────

HOST_KEY       = None
stats_lock     = threading.Lock()
rate_lock      = threading.Lock()
active_sessions: dict = {}

# {ip: [(timestamp, ...), ...]}
rate_tracker: dict = defaultdict(list)

STATS = {
    "start_time":       str(datetime.now()),
    "total_connections":0,
    "total_auth_attempts":0,
    "unique_ips":       set(),
    "total_commands":   0,
    "top_usernames":    defaultdict(int),
    "top_passwords":    defaultdict(int),
    "top_commands":     defaultdict(int),
    "top_ips":          defaultdict(int),
}

# ─────────────────────────── LOGGING SETUP ───────────────────────────────────

def setup_logging():
    os.makedirs(LOG_DIR, exist_ok=True)

    # Console logger
    console = logging.StreamHandler()
    console.setLevel(logging.INFO)
    console.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))

    # File logger (rotates at 10 MB, keeps 5 backups)
    fh = RotatingFileHandler(
        os.path.join(LOG_DIR, "honeypot.log"),
        maxBytes=10 * 1024 * 1024,
        backupCount=5,
    )
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))

    logger = logging.getLogger("honeypot")
    logger.setLevel(logging.DEBUG)
    logger.addHandler(console)
    logger.addHandler(fh)
    return logger

logger = setup_logging()


def log_json(filepath: str, data: dict):
    try:
        with open(filepath, "a") as f:
            f.write(json.dumps(data, default=str) + "\n")
    except Exception as e:
        logger.error(f"Failed to write log to {filepath}: {e}")


def save_stats():
    try:
        with stats_lock:
            exportable = {
                k: (list(v) if isinstance(v, set) else
                    dict(v) if isinstance(v, defaultdict) else v)
                for k, v in STATS.items()
            }
        with open(STATS_FILE, "w") as f:
            json.dump(exportable, f, indent=2, default=str)
    except Exception as e:
        logger.error(f"Failed to save stats: {e}")


# ─────────────────────────── RATE LIMITING ───────────────────────────────────

def is_rate_limited(ip: str) -> bool:
    now = time.time()
    window = CONFIG["rate_window"]
    limit  = CONFIG["rate_limit"]
    with rate_lock:
        rate_tracker[ip] = [t for t in rate_tracker[ip] if now - t < window]
        rate_tracker[ip].append(now)
        return len(rate_tracker[ip]) > limit


# ─────────────────────────── SSH SERVER ──────────────────────────────────────

class HoneypotServer(paramiko.ServerInterface):
    def __init__(self, client_ip: str):
        self.client_ip  = client_ip
        self.username   = None
        self.password   = None
        self.auth_time  = None

    def check_auth_password(self, username: str, password: str):
        self.username  = username
        self.password  = password
        self.auth_time = datetime.now()

        with stats_lock:
            STATS["total_auth_attempts"] += 1
            STATS["top_usernames"][username] += 1
            STATS["top_passwords"][password] += 1
            STATS["top_ips"][self.client_ip] += 1

        log_json(CRED_LOG, {
            "timestamp": str(self.auth_time),
            "event":     "auth_attempt",
            "ip":        self.client_ip,
            "username":  username,
            "password":  password,
        })
        logger.info(f"AUTH  {self.client_ip} → {username}:{password}")
        return paramiko.AUTH_SUCCESSFUL

    def check_auth_publickey(self, username, key):
        """Log public-key attempts (always deny — forces password fallback)."""
        log_json(CRED_LOG, {
            "timestamp": str(datetime.now()),
            "event":     "pubkey_attempt",
            "ip":        self.client_ip,
            "username":  username,
            "key_type":  key.get_name(),
            "key_fp":    key.get_fingerprint().hex(),
        })
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return "password,publickey"

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_shell_request(self, channel):
        return True

    def check_channel_exec_request(self, channel, command):
        return True

    def check_channel_pty_request(self, channel, term, width, height, pw, ph, modes):
        return True

    def check_channel_subsystem_request(self, channel, name):
        return False


# ─────────────────────────── SHELL SIMULATOR ─────────────────────────────────

def normalize_path(cwd: str, target: str) -> str:
    if not target:
        return "/"
    path = target if target.startswith("/") else os.path.join(cwd, target)
    normalized = os.path.normpath(path)
    return normalized if normalized.startswith("/") else "/" + normalized


def path_exists(path: str) -> bool:
    if path in FAKE_FS or path in FAKE_FILES:
        return True
    parent = os.path.dirname(path)
    name   = os.path.basename(path)
    return name in FAKE_FS.get(parent, [])


def is_directory(path: str) -> bool:
    return path in FAKE_FS


def ls_output(path: str, long_fmt: bool = False) -> str:
    entries = FAKE_FS.get(path, [])
    if not entries:
        return ""
    if long_fmt:
        lines = ["total " + str(len(entries) * 4)]
        for e in entries:
            full = os.path.join(path, e) if path != "/" else "/" + e
            is_dir = full in FAKE_FS or e in FAKE_FS.get(path, [])
            perm = "drwxr-xr-x" if is_dir else "-rw-r--r--"
            size = str(4096) if is_dir else str(len(FAKE_FILES.get(full, "")) or 1024)
            lines.append(
                f"{perm}  1 root root {size:>8} "
                f"{datetime.now().strftime('%b %d %H:%M')} {e}"
            )
        return "\n".join(lines) + "\n"
    else:
        output = ""
        for i, item in enumerate(entries):
            output += f"{item:<20}"
            if (i + 1) % 4 == 0:
                output += "\n"
        if not output.endswith("\n"):
            output += "\n"
        return output


def handle_command(channel, raw: str, cwd: str, session_data: dict) -> tuple:
    """Process command, return (new_cwd, exit_flag)."""
    command = raw.strip()
    if not command:
        return cwd, False

    # Echo back (simulate real terminal input)
    channel.send(command + "\r\n")

    with stats_lock:
        STATS["total_commands"] += 1
        STATS["top_commands"][command.split()[0] if command.split() else command] += 1

    session_data["commands"].append({
        "timestamp": str(datetime.now()),
        "command":   command,
        "cwd":       cwd,
    })
    log_json(CMD_LOG, {
        "timestamp":  str(datetime.now()),
        "session_id": session_data["session_id"],
        "ip":         session_data["ip"],
        "username":   session_data["username"],
        "cwd":        cwd,
        "command":    command,
    })

    parts   = command.split()
    cmd     = parts[0] if parts else ""
    args    = parts[1:] if len(parts) > 1 else []
    user    = session_data.get("username", "root")
    host    = "ubuntu"

    # ── Builtins & common commands ──────────────────────────────────────────

    if cmd in ("exit", "logout", "quit"):
        channel.send("logout\r\n")
        return cwd, True

    elif cmd == "clear":
        channel.send("\033[H\033[2J")

    elif cmd in ("pwd",):
        channel.send(cwd + "\r\n")

    elif cmd == "cd":
        target = args[0] if args else ("/" if user == "root" else f"/home/{user}")
        if target == "~":
            target = "/" if user == "root" else f"/home/{user}"
        new_cwd = normalize_path(cwd, target)
        if is_directory(new_cwd):
            cwd = new_cwd
        else:
            channel.send(f"bash: cd: {target}: No such file or directory\r\n")

    elif cmd == "ls":
        long_fmt  = "-l" in args or "-la" in args or "-al" in args
        show_all  = "-a" in args or "-la" in args or "-al" in args
        path_arg  = next((a for a in args if not a.startswith("-")), cwd)
        target_path = normalize_path(cwd, path_arg)
        if is_directory(target_path):
            out = ls_output(target_path, long_fmt)
            if show_all:
                prefix = "drwxr-xr-x  2 root root 4096 Jan  1 00:00 .\r\n" \
                         "drwxr-xr-x  2 root root 4096 Jan  1 00:00 ..\r\n"
                out = prefix + out
            channel.send(out if out else "\r\n")
        elif path_exists(target_path):
            channel.send(os.path.basename(target_path) + "\r\n")
        else:
            channel.send(f"ls: cannot access '{path_arg}': No such file or directory\r\n")

    elif cmd == "cat":
        if not args:
            channel.send("cat: missing file operand\r\n")
        else:
            filepath = normalize_path(cwd, args[0])
            if filepath in FAKE_FILES:
                channel.send(FAKE_FILES[filepath].replace("\n", "\r\n"))
            elif is_directory(filepath):
                channel.send(f"cat: {args[0]}: Is a directory\r\n")
            else:
                channel.send(f"cat: {args[0]}: No such file or directory\r\n")

    elif cmd == "whoami":
        channel.send(user + "\r\n")

    elif cmd == "id":
        uid = 0 if user == "root" else 1000
        gid = 0 if user == "root" else 1000
        channel.send(f"uid={uid}({user}) gid={gid}({user}) groups={gid}({user})\r\n")

    elif cmd == "hostname":
        channel.send(host + "\r\n")

    elif cmd == "uname":
        if "-a" in args:
            channel.send(
                f"Linux {host} 5.15.0-91-generic #101-Ubuntu SMP "
                "Tue Nov 14 13:30:08 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux\r\n"
            )
        elif "-r" in args:
            channel.send("5.15.0-91-generic\r\n")
        else:
            channel.send("Linux\r\n")

    elif cmd == "date":
        channel.send(datetime.now().strftime("%a %b %d %H:%M:%S UTC %Y") + "\r\n")

    elif cmd == "uptime":
        channel.send(
            f" {datetime.now().strftime('%H:%M:%S')} up 3 days,  4:17,  1 user, "
            "load average: 0.00, 0.01, 0.05\r\n"
        )

    elif cmd == "w":
        channel.send(
            f" {datetime.now().strftime('%H:%M:%S')} up 3 days,  4:17,  1 user, "
            "load average: 0.00, 0.01, 0.05\r\n"
            "USER     TTY      FROM             LOGIN@   IDLE JCPU   PCPU WHAT\r\n"
            f"{user:<8} pts/0    {session_data['ip']:<16}  "
            f"{datetime.now().strftime('%H:%M')}    0.00s  0.03s  0.00s w\r\n"
        )

    elif cmd in ("ps",):
        channel.send(
            "  PID TTY          TIME CMD\r\n"
            " 1234 pts/0    00:00:00 bash\r\n"
            " 1238 pts/0    00:00:00 ps\r\n"
        )
        if "-aux" in command or "-ef" in command or "aux" in args:
            channel.send(
                "USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\r\n"
                "root         1  0.0  0.1 168164  8960 ?        Ss   Nov14   0:12 /sbin/init\r\n"
                "root       421  0.0  0.1  47048  4356 ?        Ss   Nov14   0:00 /lib/systemd/systemd-journald\r\n"
                "root       712  0.0  0.0  15428  1060 ?        Ss   Nov14   0:00 /sbin/dhclient eth0\r\n"
                "root       812  0.0  0.1  72308  5288 ?        Ss   Nov14   0:00 /usr/sbin/sshd -D\r\n"
                "www-data  1012  0.0  0.4 428012 18300 ?        S    Nov14   0:01 apache2\r\n"
                f"{user:<10}{session_data['session_id'] % 9999:>5}  0.0  0.2  21248  4644 pts/0    Ss "
                f"   {datetime.now().strftime('%H:%M')}   0:00 -bash\r\n"
            )

    elif cmd in ("ifconfig", "ip"):
        channel.send(
            "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\r\n"
            "        inet 10.0.2.15  netmask 255.255.255.0  broadcast 10.0.2.255\r\n"
            "        inet6 fe80::a00:27ff:fe8d:c04d  prefixlen 64  scopeid 0x20<link>\r\n"
            "        ether 08:00:27:8d:c0:4d  txqueuelen 1000  (Ethernet)\r\n"
            "        RX packets 10483  bytes 1127641 (1.0 MiB)\r\n"
            "        TX packets 8132   bytes 893447  (872.5 KiB)\r\n\r\n"
            "lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536\r\n"
            "        inet 127.0.0.1  netmask 255.0.0.0\r\n"
            "        inet6 ::1  prefixlen 128  scopeid 0x10<host>\r\n"
            "        loop  txqueuelen 1000  (Local Loopback)\r\n"
        )

    elif cmd in ("netstat", "ss"):
        channel.send(
            "Active Internet connections (only servers)\r\n"
            "Proto Recv-Q Send-Q Local Address           Foreign Address         State\r\n"
            "tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN\r\n"
            "tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN\r\n"
            "tcp        0      0 0.0.0.0:443             0.0.0.0:*               LISTEN\r\n"
            "tcp        0      0 0.0.0.0:3306            0.0.0.0:*               LISTEN\r\n"
            "tcp        0      0 127.0.0.1:6379          0.0.0.0:*               LISTEN\r\n"
        )

    elif cmd in ("df",):
        channel.send(
            "Filesystem      Size  Used Avail Use% Mounted on\r\n"
            "udev            989M     0  989M   0% /dev\r\n"
            "tmpfs           200M  852K  199M   1% /run\r\n"
            "/dev/sda1        20G  6.3G   13G  34% /\r\n"
            "tmpfs           997M     0  997M   0% /dev/shm\r\n"
        )

    elif cmd in ("free",):
        channel.send(
            "               total        used        free      shared  buff/cache   available\r\n"
            "Mem:         2041344      326412     1524208        1028      190724     1575440\r\n"
            "Swap:        2097148           0     2097148\r\n"
        )

    elif cmd in ("history",):
        fake_history = [
            "ls -la", "cd /var/www/html", "cat wp-config.php",
            "ps aux", "netstat -tulnp", "cat /etc/passwd",
            "sudo su -", "wget http://example.com/script.sh",
            "chmod +x script.sh", "./script.sh", "history",
        ]
        for i, h in enumerate(fake_history, 1):
            channel.send(f"  {i:>4}  {h}\r\n")

    elif cmd in ("env", "printenv"):
        channel.send(
            f"USER={user}\r\n"
            f"HOME={'/' if user == 'root' else f'/home/{user}'}\r\n"
            f"LOGNAME={user}\r\n"
            "SHELL=/bin/bash\r\n"
            "TERM=xterm-256color\r\n"
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\r\n"
            "LANG=en_US.UTF-8\r\n"
            "PWD=" + cwd + "\r\n"
        )

    elif cmd == "echo":
        text = " ".join(args).replace("$USER", user).replace("$HOME",
               "/" if user == "root" else f"/home/{user}").replace("$PWD", cwd)
        channel.send(text + "\r\n")

    elif cmd == "sudo":
        if not args:
            channel.send("usage: sudo [-AbEHnPS] [-u user] <command>\r\n")
        elif args[0] == "su" or (args[0] == "-s" and "-" in args):
            channel.send("[sudo] password for " + user + ": \r\n")
            time.sleep(0.5)
            channel.send("Sorry, try again.\r\n")
        elif args[0] == "-l":
            channel.send(f"Matching Defaults entries for {user} on ubuntu:\r\n"
                         "    env_reset, mail_badpass\r\n\r\n"
                         f"User {user} may run the following commands on ubuntu:\r\n"
                         "    (ALL : ALL) ALL\r\n")
        else:
            sub = " ".join(args)
            channel.send(f"[sudo] password for {user}: \r\n")
            time.sleep(0.5)
            channel.send("Sorry, try again.\r\n")

    elif cmd in ("su",):
        channel.send("Password: \r\n")
        time.sleep(0.5)
        channel.send("su: Authentication failure\r\n")

    elif cmd in ("wget", "curl"):
        if not args:
            channel.send(f"{cmd}: missing URL\r\n")
        else:
            url = next((a for a in args if a.startswith("http")), args[-1])
            channel.send(f"--{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}--  {url}\r\n")
            time.sleep(0.3)
            channel.send("Resolving host... failed: Name or service not known.\r\n")
            channel.send(f"{cmd}: unable to resolve host address '{url.split('/')[2] if '/' in url else url}'\r\n")

    elif cmd in ("python3", "python"):
        channel.send(
            "Python 3.10.12 (main, Nov 20 2023, 15:14:05) [GCC 11.4.0] on linux\r\n"
            "Type \"help\", \"copyright\", \"credits\" or \"license\" for more information.\r\n"
            ">>> "
        )
        # Read a couple of lines then bail
        try:
            data = channel.recv(256)
            channel.send("\r\n")
        except Exception:
            pass
        channel.send("\r\n")

    elif cmd == "which":
        for arg in args:
            if arg in FAKE_FS.get("/usr/bin", []) or arg in FAKE_FS.get("/bin", []):
                channel.send(f"/usr/bin/{arg}\r\n")
            else:
                channel.send(f"{arg} not found\r\n")

    elif cmd == "find":
        channel.send("")  # Silently do nothing (realistic for complex finds)

    elif cmd in ("touch", "mkdir"):
        pass  # Silent success

    elif cmd in ("rm", "rmdir"):
        if "-rf" in args and ("/" in args or "/*" in args):
            channel.send("rm: it is dangerous to operate recursively on '/'\r\n"
                         "rm: use --no-preserve-root to override this failsafe\r\n")
        else:
            pass  # Silent success

    elif cmd in ("chmod", "chown"):
        pass  # Silent success

    elif cmd == "service" or cmd == "systemctl":
        channel.send("System has not been booted with systemd as init system (PID 1). "
                     "Can't operate.\r\n"
                     "Failed to connect to bus: Host is down\r\n")

    elif cmd == "crontab":
        if "-l" in args:
            channel.send("# no crontab for " + user + "\r\n")

    elif cmd == "help":
        channel.send(
            "GNU bash, version 5.1.16(1)-release (x86_64-pc-linux-gnu)\r\n"
            "These shell commands are defined internally. Type `help' to see this list.\r\n"
            "Type `help name' to find out more about the function `name'.\r\n\r\n"
            " cd [-L|[-P [-e]] [-@]] [dir]     exit [n]\r\n"
            " echo [-neE] [arg ...]             pwd [-LP]\r\n"
            " history [-c] [-d offset]          whoami\r\n"
            " ls                               uname [-a]\r\n"
        )

    elif cmd in ("nano", "vim", "vi"):
        fname = args[0] if args else ""
        channel.send(f"\r\n[Fake editor] {cmd}: {fname}\r\n"
                     "  [Press Ctrl+C to exit]\r\n")
        try:
            channel.recv(256)
        except Exception:
            pass
        channel.send("\r\n")

    else:
        channel.send(f"bash: {cmd}: command not found\r\n")

    return cwd, False


# ─────────────────────────── CONNECTION HANDLER ──────────────────────────────

def handle_connection(client_sock, addr):
    client_ip = addr[0]

    # Rate limit check
    if is_rate_limited(client_ip):
        logger.warning(f"RATE-LIMITED {client_ip} — dropping connection")
        client_sock.close()
        return

    with stats_lock:
        STATS["total_connections"] += 1
        STATS["unique_ips"].add(client_ip)

    transport = None
    try:
        transport = paramiko.Transport(client_sock)
        transport.local_version = CONFIG["server_version"]
        transport.add_server_key(HOST_KEY)

        server = HoneypotServer(client_ip)
        transport.start_server(server=server)

        channel = transport.accept(30)
        if not channel:
            logger.debug(f"No channel from {client_ip}")
            return

        channel.settimeout(CONFIG["idle_timeout"])

        session_id = int(time.time() * 1000) % 0xFFFF
        session_data = {
            "session_id": session_id,
            "start_time": str(datetime.now()),
            "ip":         client_ip,
            "port":       addr[1],
            "username":   server.username,
            "password":   server.password,
            "commands":   [],
        }

        active_sessions[session_id] = session_data
        logger.info(f"SESSION  #{session_id}  {client_ip}  {server.username}:{server.password}")

        # MOTD
        now  = datetime.now().strftime("%a %b %d %H:%M:%S UTC %Y")
        last = datetime.now().strftime("%a %b %d %H:%M:%S")
        channel.send(CONFIG["motd"].format(now=now, last=last).replace("\n", "\r\n"))

        user = server.username or "root"
        home = "/" if user == "root" else f"/home/{user}"
        cwd  = home if home in FAKE_FS else "/"

        # Input buffer (handles backspace, arrow keys, multi-byte sequences)
        def prompt(cur_cwd):
            sym = "#" if user == "root" else "$"
            channel.send(f"\r\n{user}@ubuntu:{cur_cwd}{sym} ")

        prompt(cwd)
        buf = ""

        while True:
            try:
                data = channel.recv(1)
                if not data:
                    break

                ch = data.decode("utf-8", errors="ignore")

                if ch in ("\r", "\n"):
                    new_cwd, done = handle_command(channel, buf, cwd, session_data)
                    buf = ""
                    if done:
                        break
                    cwd = new_cwd
                    prompt(cwd)
                elif ch == "\x7f" or ch == "\x08":   # Backspace
                    if buf:
                        buf = buf[:-1]
                        channel.send("\x08 \x08")
                elif ch == "\x03":                    # Ctrl+C
                    channel.send("^C\r\n")
                    buf = ""
                    prompt(cwd)
                elif ch == "\x04":                    # Ctrl+D
                    channel.send("logout\r\n")
                    break
                elif ch == "\x1b":                    # Escape / arrow keys (ignore)
                    channel.recv(2)
                elif ch.isprintable():
                    buf += ch
                    channel.send(ch)

            except socket.timeout:
                channel.send("\r\nConnection timed out.\r\n")
                break
            except EOFError:
                break
            except Exception as e:
                logger.debug(f"Shell error [{client_ip}]: {e}")
                break

        session_data["end_time"] = str(datetime.now())
        session_data["final_cwd"] = cwd
        log_json(SESSION_LOG, session_data)
        active_sessions.pop(session_id, None)

        logger.info(
            f"ENDED  #{session_id}  {client_ip}  "
            f"cmds={len(session_data['commands'])}"
        )

    except paramiko.SSHException as e:
        logger.debug(f"SSH error [{client_ip}]: {e}")
    except Exception as e:
        logger.debug(f"Connection error [{client_ip}]: {e}")
    finally:
        if transport:
            try:
                transport.close()
            except Exception:
                pass
        try:
            client_sock.close()
        except Exception:
            pass


# ─────────────────────────── STARTUP & MAIN ──────────────────────────────────

def generate_or_load_host_key() -> paramiko.RSAKey:
    os.makedirs(CONFIG["base_dir"], exist_ok=True)
    if os.path.exists(KEY_PATH):
        logger.info(f"Loaded existing host key from {KEY_PATH}")
        return paramiko.RSAKey(filename=KEY_PATH)
    else:
        logger.info(f"Generating new RSA 2048 host key → {KEY_PATH}")
        key = paramiko.RSAKey.generate(2048)
        key.write_private_key_file(KEY_PATH)
        os.chmod(KEY_PATH, 0o600)
        return key


def print_banner():
    print(r"""
  ____                                     ____        _
 |  _ \  ___ _ __ ___   ___  _ __        |  _ \ ___  | |_
 | | | |/ _ \ '_ ` _ \ / _ \| '_ \ ___  | |_) / _ \ | __|
 | |_| |  __/ | | | | | (_) | | | |___| |  __/ (_) || |_
 |____/ \___|_| |_| |_|\___/|_| |_|     |_|   \___/  \__|

   Advanced SSH Honeypot  |  Educational Use Only
""")


def shutdown_handler(sig, frame):
    logger.info("Shutdown signal received — saving stats and exiting...")
    save_stats()
    # Print summary
    with stats_lock:
        print("\n── Session Summary ──────────────────────────────────")
        print(f"  Total connections  : {STATS['total_connections']}")
        print(f"  Auth attempts      : {STATS['total_auth_attempts']}")
        print(f"  Unique IPs         : {len(STATS['unique_ips'])}")
        print(f"  Commands captured  : {STATS['total_commands']}")
        if STATS["top_usernames"]:
            top_u = sorted(STATS["top_usernames"].items(), key=lambda x: -x[1])[:5]
            print(f"  Top usernames      : {', '.join(f'{u}({c})' for u,c in top_u)}")
        if STATS["top_passwords"]:
            top_p = sorted(STATS["top_passwords"].items(), key=lambda x: -x[1])[:5]
            print(f"  Top passwords      : {', '.join(f'{p}({c})' for p,c in top_p)}")
        print("─────────────────────────────────────────────────────\n")
    sys.exit(0)


def main():
    parser = argparse.ArgumentParser(description="Demon-Pot SSH Honeypot")
    parser.add_argument("-p", "--port",  type=int, default=CONFIG["port"],
                        help=f"Port to listen on (default: {CONFIG['port']})")
    parser.add_argument("-b", "--bind",  default=CONFIG["bind"],
                        help=f"Bind address (default: {CONFIG['bind']})")
    parser.add_argument("--base-dir",    default=CONFIG["base_dir"],
                        help=f"Base directory (default: {CONFIG['base_dir']})")
    args = parser.parse_args()

    CONFIG["port"]     = args.port
    CONFIG["bind"]     = args.bind
    CONFIG["base_dir"] = args.base_dir

    global LOG_DIR, KEY_PATH, SESSION_LOG, CRED_LOG, CMD_LOG, STATS_FILE
    LOG_DIR     = os.path.join(CONFIG["base_dir"], "logs")
    KEY_PATH    = os.path.join(CONFIG["base_dir"], "ssh_host_rsa_key")
    SESSION_LOG = os.path.join(LOG_DIR, "sessions.jsonl")
    CRED_LOG    = os.path.join(LOG_DIR, "credentials.jsonl")
    CMD_LOG     = os.path.join(LOG_DIR, "commands.jsonl")
    STATS_FILE  = os.path.join(LOG_DIR, "stats.json")

    print_banner()
    os.makedirs(LOG_DIR, exist_ok=True)

    global HOST_KEY
    HOST_KEY = generate_or_load_host_key()

    signal.signal(signal.SIGINT,  shutdown_handler)
    signal.signal(signal.SIGTERM, shutdown_handler)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.settimeout(1.0)

    try:
        sock.bind((CONFIG["bind"], CONFIG["port"]))
        sock.listen(CONFIG["max_connections"])
        logger.info(f"Listening on {CONFIG['bind']}:{CONFIG['port']}")
        logger.info(f"Logs → {LOG_DIR}")
        logger.info("Press Ctrl+C to stop\n")

        while True:
            try:
                client, addr = sock.accept()
                client.settimeout(CONFIG["idle_timeout"])
                t = threading.Thread(
                    target=handle_connection,
                    args=(client, addr),
                    daemon=True,
                )
                t.start()
            except socket.timeout:
                continue
            except Exception as e:
                logger.error(f"Accept error: {e}")

    finally:
        sock.close()
        logger.info("Socket closed.")


if __name__ == "__main__":
    main()
