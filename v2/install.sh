#!/bin/bash
# ─────────────────────────────────────────────────────────────
#  Demon-Pot SSH Honeypot — Installer
#  Run as root or with sudo on Ubuntu/Debian
# ─────────────────────────────────────────────────────────────
set -e

INSTALL_DIR="/opt/ssh-honeypot"
SERVICE="ssh-honeypot"
HONEYPOT_USER="honeypot"

echo "╔══════════════════════════════════════════════════╗"
echo "║        Demon-Pot SSH Honeypot Installer          ║"
echo "╚══════════════════════════════════════════════════╝"
echo ""

# ── 1. System dependencies ──────────────────────────────────
echo "[1/6] Installing system dependencies..."
apt-get update -qq
apt-get install -y -qq python3 python3-pip python3-venv

# ── 2. Dedicated system user ────────────────────────────────
echo "[2/6] Setting up honeypot user..."
if ! id "$HONEYPOT_USER" &>/dev/null; then
    useradd -r -s /bin/false -M -d "$INSTALL_DIR" "$HONEYPOT_USER"
    echo "      Created user: $HONEYPOT_USER"
else
    echo "      User '$HONEYPOT_USER' already exists — skipping"
fi

# ── 3. Directory structure ───────────────────────────────────
echo "[3/6] Creating directory structure..."
mkdir -p "$INSTALL_DIR/logs"

# ── 4. Copy files ───────────────────────────────────────────
echo "[4/6] Copying honeypot files..."
cp honeypot.py     "$INSTALL_DIR/"
cp requirements.txt "$INSTALL_DIR/"
[ -f README.md ]   && cp README.md   "$INSTALL_DIR/"
[ -f OPERATION.md ] && cp OPERATION.md "$INSTALL_DIR/"

# ── 5. Python virtual environment & deps ────────────────────
echo "[5/6] Installing Python dependencies..."
python3 -m venv "$INSTALL_DIR/venv"
"$INSTALL_DIR/venv/bin/pip" install --quiet --upgrade pip
"$INSTALL_DIR/venv/bin/pip" install --quiet -r "$INSTALL_DIR/requirements.txt"

# Fix ownership and permissions
chown -R "$HONEYPOT_USER:$HONEYPOT_USER" "$INSTALL_DIR"
chmod 750 "$INSTALL_DIR"
chmod 750 "$INSTALL_DIR/logs"
chmod 640 "$INSTALL_DIR/honeypot.py"
# RSA key (created on first run, pre-lock if it already exists)
[ -f "$INSTALL_DIR/ssh_host_rsa_key" ] && \
    chmod 600 "$INSTALL_DIR/ssh_host_rsa_key"

# ── 6. Systemd service ──────────────────────────────────────
echo "[6/6] Installing systemd service..."
cp ssh-honeypot.service /etc/systemd/system/"$SERVICE".service
systemctl daemon-reload
systemctl enable "$SERVICE"
systemctl restart "$SERVICE"

# Verify
sleep 3
if systemctl is-active --quiet "$SERVICE"; then
    echo ""
    echo "╔══════════════════════════════════════════════════╗"
    echo "║        ✓  Demon-Pot is running!                  ║"
    echo "╠══════════════════════════════════════════════════╣"
    echo "║  Port     : 2222                                  ║"
    echo "║  Logs     : $INSTALL_DIR/logs/         ║"
    echo "║  Status   : systemctl status $SERVICE  ║"
    echo "║  Test     : ssh -p 2222 test@localhost            ║"
    echo "║  Live log : journalctl -u $SERVICE -f  ║"
    echo "╚══════════════════════════════════════════════════╝"
else
    echo "[!] Service failed to start. Showing last 30 log lines:"
    journalctl -u "$SERVICE" -n 30 --no-pager
    exit 1
fi
