#!/bin/bash
##############################################################
# NET-WATCH — Ubuntu Server Laptop Install Script
#
# What this script does, in plain English:
#   1. Checks everything you need before changing anything
#   2. Installs system packages (nmap, arp-scan, nginx, python3-pip)
#   3. Installs Python libraries (Flask, flask-cors, requests)
#   4. Copies your netwatch project files to /opt/netwatch
#   5. Installs the systemd service (auto-start on boot)
#   6. Installs and enables the Nginx site config
#   7. Opens the firewall port for HTTP (port 80)
#   8. Tells you your server's IP so you can open the dashboard
#
# How to run it (from the folder containing this file):
#   chmod +x setup.sh
#   sudo ./setup.sh
#
# NOTE: This script must be run with sudo (root privileges)
# because it installs software and writes to /etc and /opt.
##############################################################

set -e  # exit immediately if any command fails

# ── Colors for readable output ────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
RESET='\033[0m'

ok()   { echo -e "${GREEN}  ✓ $1${RESET}"; }
info() { echo -e "${CYAN}  → $1${RESET}"; }
warn() { echo -e "${YELLOW}  ⚠  $1${RESET}"; }
fail() { echo -e "${RED}  ✗ $1${RESET}"; exit 1; }
step() { echo -e "\n${BOLD}$1${RESET}"; }

# ── 0. Must be root ───────────────────────────────────────
if [ "$EUID" -ne 0 ]; then
    fail "Please run with sudo: sudo ./setup.sh"
fi

# ── 1. Detect the script's own location so we can find the project files
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo -e "\n${BOLD}╔══════════════════════════════════════╗${RESET}"
echo -e "${BOLD}║   NET-WATCH — Ubuntu Server Setup   ║${RESET}"
echo -e "${BOLD}╚══════════════════════════════════════╝${RESET}"
echo ""
info "Project files found at: $SCRIPT_DIR"
info "Files will be installed to: /opt/netwatch"

# ── 2. Pre-flight checks ──────────────────────────────────
step "STEP 1 — Checking your system"

OS=$(lsb_release -is 2>/dev/null || echo "Unknown")
if [[ "$OS" != "Ubuntu" && "$OS" != "Debian" ]]; then
    warn "This script was written for Ubuntu/Debian. You're running: $OS"
    warn "It may still work, but some package names might differ."
fi

PYTHON_VER=$(python3 --version 2>/dev/null | awk '{print $2}' || echo "missing")
if [[ "$PYTHON_VER" == "missing" ]]; then
    fail "Python 3 is not installed. Install it with: sudo apt install python3"
fi
ok "Python 3 found: $PYTHON_VER"

# Check all the project files are actually present before proceeding
for f in api/netwatch_api.py config/devices.json config/profiles.json web/index.html; do
    if [ ! -f "$SCRIPT_DIR/$f" ]; then
        fail "Missing project file: $f — make sure you're running this from the netwatch folder"
    fi
done
ok "All project files present"

# ── 3. Install system packages ────────────────────────────
step "STEP 2 — Installing system packages"
info "Running apt update..."
apt-get update -qq

PACKAGES=""
CADDY_ACTIVE=false
if command -v caddy &>/dev/null && systemctl is-active --quiet caddy; then
    CADDY_ACTIVE=true
    REQUIRED_PACKAGES="nmap arp-scan vnstat python3-venv"
    ok "Active Caddy installation detected — preserving it"
else
    REQUIRED_PACKAGES="nmap arp-scan nginx vnstat python3-venv"
fi
for pkg in $REQUIRED_PACKAGES; do
    if dpkg -s "$pkg" &>/dev/null; then
        ok "$pkg is already installed"
    else
        PACKAGES="$PACKAGES $pkg"
    fi
done

if [ -n "$PACKAGES" ]; then
    info "Installing:$PACKAGES"
    apt-get install -y $PACKAGES
    ok "Packages installed"
else
    ok "All system packages already installed"
fi

# ── 4. Install Python libraries ───────────────────────────
step "STEP 3 — Installing Python libraries"

mkdir -p /opt/netwatch
if [ ! -x /opt/netwatch/venv/bin/python ]; then
    info "Creating isolated Python environment..."
    python3 -m venv /opt/netwatch/venv
fi

info "Installing/updating Flask dependencies in the isolated environment..."
/opt/netwatch/venv/bin/python -m pip install --upgrade pip -q
/opt/netwatch/venv/bin/python -m pip install --upgrade flask flask-cors requests -q

for lib in flask flask_cors requests; do
    /opt/netwatch/venv/bin/python -c "import $lib" &>/dev/null || fail "$lib installation failed"
done
ok "Python environment ready at /opt/netwatch/venv"

# ── 5. Copy project files to /opt/netwatch ───────────────
step "STEP 4 — Installing NET-WATCH files to /opt/netwatch"

if [ -d /opt/netwatch ]; then
    warn "/opt/netwatch already exists — updating files"
fi

mkdir -p /opt/netwatch/api /opt/netwatch/web /opt/netwatch/config

# Copy code files (always overwrite — these are updated code)
cp -f "$SCRIPT_DIR/api/netwatch_api.py"   /opt/netwatch/api/
cp -f "$SCRIPT_DIR/web/index.html"        /opt/netwatch/web/

# Config files: only copy if they don't already exist, so existing
# device/profile data is not wiped when you update the code.
if [ ! -f /opt/netwatch/config/devices.json ]; then
    cp -f "$SCRIPT_DIR/config/devices.json" /opt/netwatch/config/
    ok "devices.json installed (new)"
else
    ok "devices.json already exists — keeping your data"
fi

if [ ! -f /opt/netwatch/config/profiles.json ]; then
    cp -f "$SCRIPT_DIR/config/profiles.json" /opt/netwatch/config/
    ok "profiles.json installed (new)"
else
    ok "profiles.json already exists — keeping your data"
fi

# Set permissions — Flask runs as root for arp-scan, but config
# files should still be readable by the owner
chmod 644 /opt/netwatch/config/*.json
chmod 644 /opt/netwatch/web/index.html
chmod 755 /opt/netwatch/api/netwatch_api.py

ok "Files installed to /opt/netwatch"

# ── 6. Install and start the systemd service ─────────────
step "STEP 5 — Creating protected runtime configuration"

mkdir -p /etc/netwatch
chmod 700 /etc/netwatch

if [ ! -f /etc/netwatch/netwatch.env ]; then
    NETWATCH_PASSWORD_VALUE="${NETWATCH_PASSWORD:-}"
    if [ -z "$NETWATCH_PASSWORD_VALUE" ] && [ -t 0 ]; then
        read -r -s -p "  Enter a strong NET-WATCH dashboard password: " NETWATCH_PASSWORD_VALUE
        echo
    fi
    [ -n "$NETWATCH_PASSWORD_VALUE" ] || fail "Set NETWATCH_PASSWORD or run setup interactively"
    NETWATCH_SECRET_VALUE="${NETWATCH_SECRET:-$(python3 -c 'import secrets; print(secrets.token_hex(32))')}"
    PRIMARY_IF=$(ip route show default | awk 'NR==1 {print $5}')
    PRIMARY_CIDR=$(ip -o -4 route show dev "$PRIMARY_IF" proto kernel scope link | awk 'NR==1 {print $1}')
    [ -n "$PRIMARY_IF" ] && [ -n "$PRIMARY_CIDR" ] || fail "Could not detect the primary interface/subnet"
    {
        printf 'NETWATCH_PASSWORD=%s\n' "$NETWATCH_PASSWORD_VALUE"
        printf 'NETWATCH_SECRET=%s\n' "$NETWATCH_SECRET_VALUE"
        printf 'SCAN_SUBNETS_JSON=[{"subnet":"%s","interface":"%s"}]\n' "$PRIMARY_CIDR" "$PRIMARY_IF"
        printf 'PIHOLE_ENABLED=false\n'
        printf 'WAZUH_ENABLED=false\n'
    } > /etc/netwatch/netwatch.env
    chmod 600 /etc/netwatch/netwatch.env
    ok "Protected config created at /etc/netwatch/netwatch.env"
else
    ok "Protected config already exists — keeping existing secrets and network settings"
fi
systemctl enable --now vnstat

step "STEP 6 — Setting up the NET-WATCH service (auto-start on boot)"

# If the service is already running, stop it before overwriting
if systemctl is-active --quiet netwatch 2>/dev/null; then
    info "Stopping existing NET-WATCH service..."
    systemctl stop netwatch
fi

cp -f "$SCRIPT_DIR/netwatch.service" /etc/systemd/system/netwatch.service
systemctl daemon-reload
systemctl enable netwatch
systemctl start netwatch

sleep 2  # give Flask a moment to bind the port

if systemctl is-active --quiet netwatch; then
    ok "NET-WATCH service is running"
else
    warn "Service did not start correctly — checking logs:"
    journalctl -u netwatch -n 20 --no-pager
    fail "Service failed to start. Fix the error above and re-run this script."
fi

# ── 7. Configure the existing web server ─────────────────
step "STEP 6 — Configuring web server"

if [ "$CADDY_ACTIVE" = true ]; then
    cp -f /etc/caddy/Caddyfile "/etc/caddy/Caddyfile.netwatch-backup-$(date +%Y%m%d%H%M%S)"
    cp -f "$SCRIPT_DIR/caddy-netwatch.conf" /etc/caddy/netwatch.Caddyfile
    caddy fmt --overwrite /etc/caddy/netwatch.Caddyfile
    if ! grep -Fqx 'import /etc/caddy/netwatch.Caddyfile' /etc/caddy/Caddyfile; then
        printf '\nimport /etc/caddy/netwatch.Caddyfile\n' >> /etc/caddy/Caddyfile
    fi
    if caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile; then
        systemctl reload caddy
        ok "Caddy reloaded with NET-WATCH at https://netwatch.coc-srv-01.home.arpa"
    else
        fail "Caddy validation failed; restore the timestamped Caddyfile backup"
    fi
else
    cp -f "$SCRIPT_DIR/nginx-netwatch.conf" /etc/nginx/sites-available/netwatch
    ln -sf /etc/nginx/sites-available/netwatch /etc/nginx/sites-enabled/netwatch
    rm -f /etc/nginx/sites-enabled/default
    if nginx -t; then
        systemctl enable --now nginx
        systemctl reload nginx
        ok "Nginx reloaded with NET-WATCH config"
    else
        fail "Nginx configuration test failed"
    fi
fi

# ── 8. Firewall ───────────────────────────────────────────
step "STEP 7 — Opening firewall port 80 (HTTP)"

if command -v ufw &>/dev/null; then
    if ufw status | grep -q "Status: active"; then
        ufw allow 80/tcp comment "NET-WATCH dashboard HTTP" &>/dev/null
        ufw allow 443/tcp comment "NET-WATCH dashboard HTTPS" &>/dev/null
        ok "UFW: dashboard web ports opened"
    else
        info "UFW is installed but not active — skipping (port 80 is already accessible)"
    fi
else
    info "UFW not installed — if you're using iptables/nftables, open port 80 manually"
fi

# ── 9. Done — show the access URL ────────────────────────
step "STEP 8 — Finding your server's IP address"

# Get all non-loopback IPv4 addresses
ADDRS=$(ip -4 addr show | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | grep -v 127.0.0.1)
PRIMARY_IP=$(echo "$ADDRS" | head -1)

echo ""
echo -e "${GREEN}${BOLD}╔══════════════════════════════════════════╗${RESET}"
echo -e "${GREEN}${BOLD}║   ✅  NET-WATCH INSTALLED SUCCESSFULLY   ║${RESET}"
echo -e "${GREEN}${BOLD}╚══════════════════════════════════════════╝${RESET}"
echo ""
echo -e "  ${BOLD}Dashboard URL:${RESET}"
if [ "$CADDY_ACTIVE" = true ]; then
    echo -e "    ${CYAN}https://netwatch.coc-srv-01.home.arpa${RESET}"
else
    for addr in $ADDRS; do
        echo -e "    ${CYAN}http://$addr${RESET}"
    done
fi
echo ""
echo -e "  ${BOLD}Open this URL in any browser on your network${RESET}"
echo -e "  (works on your Galaxy Tab, phone, laptop, or desktop)"
echo ""
echo -e "  ${BOLD}Management commands:${RESET}"
echo -e "    Check status : ${CYAN}systemctl status netwatch${RESET}"
echo -e "    View logs    : ${CYAN}journalctl -u netwatch -f${RESET}"
echo -e "    Restart API  : ${CYAN}systemctl restart netwatch${RESET}"
echo -e "    Update files : ${CYAN}sudo ./setup.sh${RESET}  (re-run anytime)"
echo ""
echo -e "  ${BOLD}Next steps:${RESET}"
echo -e "  1. Open the dashboard and go to ${CYAN}Settings${RESET}"
echo -e "  2. Set your Pi-hole IP and password in netwatch_api.py"
echo -e "  3. Run ${CYAN}curl http://localhost:8082/api/health${RESET} to verify"
echo -e "  4. Set PIHOLE_ENABLED = True and restart the service"
echo ""
