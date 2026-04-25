#!/bin/bash
# ─────────────────────────────────────────────────────────────
#  Demon-Pot — Port Disguise Setup
#
#  Moves your real SSH to a private port, then silently
#  redirects external port 22 into the honeypot on 2222.
#
#  Result:
#    - Bots & attackers → port 22 → honeypot (port 2222)
#    - You              → port REAL_SSH_PORT → your real shell
#
#  Usage:
#    sudo ./setup_port_forward.sh [--undo]
# ─────────────────────────────────────────────────────────────
set -euo pipefail

REAL_SSH_PORT="${REAL_SSH_PORT:-50022}"
HONEYPOT_PORT="${HONEYPOT_PORT:-2222}"
DECOY_PORT=22
RULES_FILE="/etc/iptables/demon-pot.rules"
SSHD_CONFIG="/etc/ssh/sshd_config"

# ── Colour helpers ───────────────────────────────────────────
info()  { echo -e "\033[96m[INFO]\033[0m  $*"; }
ok()    { echo -e "\033[92m[ OK ]\033[0m  $*"; }
warn()  { echo -e "\033[93m[WARN]\033[0m  $*"; }
error() { echo -e "\033[91m[ERR ]\033[0m  $*" >&2; exit 1; }
bold()  { echo -e "\033[1m$*\033[0m"; }

# ── Root check ───────────────────────────────────────────────
[[ $EUID -ne 0 ]] && error "This script must be run as root."

# ── Undo mode ────────────────────────────────────────────────
if [[ "${1:-}" == "--undo" ]]; then
    bold "\n── Removing Demon-Pot port forwarding rules ──\n"
    iptables -t nat -D PREROUTING -p tcp --dport "$DECOY_PORT" \
        -j REDIRECT --to-port "$HONEYPOT_PORT" 2>/dev/null && \
        ok "Removed PREROUTING redirect rule" || \
        warn "Redirect rule not found (already removed?)"
    iptables -D INPUT -p tcp --dport "$DECOY_PORT" \
        -j DROP 2>/dev/null && \
        ok "Removed INPUT DROP rule" || \
        warn "DROP rule not found"
    rm -f "$RULES_FILE"
    ok "Done. Restore your sshd_config port manually if needed."
    exit 0
fi

bold "\n╔══════════════════════════════════════════════════╗"
bold "║     Demon-Pot Port Disguise Configuration        ║"
bold "╚══════════════════════════════════════════════════╝\n"

# ── Step 1: Verify real SSH is accessible on new port ────────
info "Step 1 — Checking current sshd port..."
CURRENT_PORT=$(grep -E "^Port " "$SSHD_CONFIG" | awk '{print $2}' || echo "22")
info "sshd is currently on port: $CURRENT_PORT"

if [[ "$CURRENT_PORT" == "22" ]]; then
    warn "Your real SSH is still on port 22."
    warn "Changing it to $REAL_SSH_PORT before enabling the honeypot redirect."
    warn ""
    warn "⚠ IMPORTANT: Open a second SSH session on port $REAL_SSH_PORT to"
    warn "  confirm access BEFORE closing this session."
    echo ""
    read -r -p "Press ENTER to proceed, or Ctrl+C to abort: "

    # Update sshd_config
    sed -i "s/^#*Port .*/Port $REAL_SSH_PORT/" "$SSHD_CONFIG"
    if ! grep -qE "^Port " "$SSHD_CONFIG"; then
        echo "Port $REAL_SSH_PORT" >> "$SSHD_CONFIG"
    fi

    ok "sshd_config updated → Port $REAL_SSH_PORT"

    # Allow new port through UFW if active
    if command -v ufw &>/dev/null && ufw status | grep -q "Status: active"; then
        ufw allow "$REAL_SSH_PORT/tcp" comment "Real SSH — Demon-Pot setup" >/dev/null
        ok "UFW: allowed port $REAL_SSH_PORT"
    fi

    # Restart sshd
    systemctl restart sshd
    ok "sshd restarted on port $REAL_SSH_PORT"
    echo ""
    bold "  ╔══════════════════════════════════════════════════╗"
    bold "  ║  ⚠  Your real SSH is now on port $REAL_SSH_PORT          ║"
    bold "  ║  Test it NOW in a new terminal:                   ║"
    bold "  ║    ssh -p $REAL_SSH_PORT user@<your-ip>              ║"
    bold "  ╚══════════════════════════════════════════════════╝"
    echo ""
    read -r -p "Confirmed access on port $REAL_SSH_PORT? (yes/no): " confirm
    [[ "$confirm" != "yes" ]] && error "Aborted. Revert sshd_config manually."
fi

# ── Step 2: Enable IP forwarding ─────────────────────────────
info "Step 2 — Enabling IP forwarding..."
sysctl -w net.ipv4.ip_forward=1 >/dev/null
grep -qxF "net.ipv4.ip_forward=1" /etc/sysctl.conf || \
    echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
ok "IP forwarding enabled (persistent)"

# ── Step 3: Apply iptables rules ─────────────────────────────
info "Step 3 — Adding iptables NAT redirect rules..."

# Remove old rules if they exist (idempotent)
iptables -t nat -D PREROUTING -p tcp --dport "$DECOY_PORT" \
    -j REDIRECT --to-port "$HONEYPOT_PORT" 2>/dev/null || true
iptables -D INPUT -p tcp --dport "$DECOY_PORT" \
    -j DROP 2>/dev/null || true

# Port 22 → Honeypot 2222 (via NAT, before routing decision)
iptables -t nat -A PREROUTING \
    -p tcp --dport "$DECOY_PORT" \
    -j REDIRECT --to-port "$HONEYPOT_PORT"

ok "NAT PREROUTING: TCP port $DECOY_PORT → $HONEYPOT_PORT"

# ── Step 4: Persist rules across reboots ─────────────────────
info "Step 4 — Persisting iptables rules..."
apt-get install -y -qq iptables-persistent 2>/dev/null || true
mkdir -p /etc/iptables
iptables-save > "$RULES_FILE"
iptables-save > /etc/iptables/rules.v4
ok "Rules saved to $RULES_FILE and /etc/iptables/rules.v4"

# ── Step 5: UFW allow honeypot port ──────────────────────────
info "Step 5 — Configuring UFW..."
if command -v ufw &>/dev/null && ufw status | grep -q "Status: active"; then
    ufw allow "$HONEYPOT_PORT/tcp" comment "Demon-Pot honeypot" >/dev/null
    ok "UFW: allowed port $HONEYPOT_PORT (honeypot)"
else
    warn "UFW not active — ensure port $HONEYPOT_PORT is reachable from outside"
fi

# ── Summary ───────────────────────────────────────────────────
echo ""
bold "╔══════════════════════════════════════════════════════╗"
bold "║          ✓  Port Disguise Active!                    ║"
bold "╠══════════════════════════════════════════════════════╣"
printf  "║  External port %-5s → Honeypot on %-5s            ║\n" "$DECOY_PORT" "$HONEYPOT_PORT"
printf  "║  Your real SSH  → Port %-5s                        ║\n" "$REAL_SSH_PORT"
bold "╠══════════════════════════════════════════════════════╣"
bold "║  To undo:  sudo ./setup_port_forward.sh --undo       ║"
bold "╚══════════════════════════════════════════════════════╝"
echo ""
info "Attackers hitting port $DECOY_PORT will land in the honeypot."
info "You connect on port $REAL_SSH_PORT as normal."
