#!/bin/bash
set -euo pipefail

# BTAK - Installer
# Installs to /opt/btak and configures systemd services

INSTALL_DIR="/opt/btak"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[+]${NC} $1"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
error() { echo -e "${RED}[-]${NC} $1"; exit 1; }

# ─── Preflight checks ───
echo "=== BTAK Installer ==="
echo ""

# Check root
if [ "$(id -u)" -ne 0 ]; then
    error "Run as root: sudo bash install.sh"
fi

# Check Python 3.10+
if ! command -v python3 &>/dev/null; then
    error "Python 3 not found. Install Python 3.10+ first."
fi

PY_VER=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
PY_MAJOR=$(echo "$PY_VER" | cut -d. -f1)
PY_MINOR=$(echo "$PY_VER" | cut -d. -f2)
if [ "$PY_MAJOR" -lt 3 ] || ([ "$PY_MAJOR" -eq 3 ] && [ "$PY_MINOR" -lt 10 ]); then
    error "Python 3.10+ required (found $PY_VER)"
fi
info "Python $PY_VER found"

# ─── Create directory structure ───
info "Creating ${INSTALL_DIR}/"
mkdir -p "${INSTALL_DIR}"/{src,static/archive}

# ─── Copy files ───
info "Copying source files"
cp "${SCRIPT_DIR}/src/poller.py"  "${INSTALL_DIR}/src/poller.py"
cp "${SCRIPT_DIR}/src/server.py"  "${INSTALL_DIR}/src/server.py"

info "Copying frontend"
cp "${SCRIPT_DIR}/frontend/index.html" "${INSTALL_DIR}/static/index.html"

# ─── Install Python dependencies ───
info "Installing Python dependencies (pyyaml)"
# Try apt first (works on SO/Ubuntu without pip issues), fall back to pip
if command -v apt &>/dev/null; then
    apt install -y python3-yaml &>/dev/null && info "Installed python3-yaml via apt" || true
fi
python3 -c "import yaml" 2>/dev/null || {
    pip3 install --quiet pyyaml 2>/dev/null || pip3 install --quiet --break-system-packages pyyaml 2>/dev/null || {
        error "Could not install pyyaml. Run: sudo apt install python3-yaml"
        exit 1
    }
}

# ─── Configuration ───
if [ ! -f "${INSTALL_DIR}/config.yaml" ]; then
    cp "${SCRIPT_DIR}/config.example.yaml" "${INSTALL_DIR}/config.yaml"
    warn "Config created at ${INSTALL_DIR}/config.yaml -- edit this file!"
    echo ""

    # Prompt for ES credentials
    read -rp "Elasticsearch host [https://localhost:9200]: " es_host
    es_host="${es_host:-https://localhost:9200}"
    sed -i "s|https://localhost:9200|${es_host}|" "${INSTALL_DIR}/config.yaml"

    read -rp "Elasticsearch username [so_elastic]: " es_user
    es_user="${es_user:-so_elastic}"
    sed -i "s|so_elastic|${es_user}|" "${INSTALL_DIR}/config.yaml"

    read -rsp "Elasticsearch password: " es_pass
    echo ""
    if [ -n "$es_pass" ]; then
        # Store in environment file for systemd
        cat > "${INSTALL_DIR}/.env" <<EOF
ES_PASSWORD=${es_pass}
ATTACKMAP_CONFIG=${INSTALL_DIR}/config.yaml
EOF
        chmod 600 "${INSTALL_DIR}/.env"
        info "Credentials saved to ${INSTALL_DIR}/.env (mode 600)"
    else
        warn "No password set. Export ES_PASSWORD before starting services."
        cat > "${INSTALL_DIR}/.env" <<EOF
ES_PASSWORD=
ATTACKMAP_CONFIG=${INSTALL_DIR}/config.yaml
EOF
        chmod 600 "${INSTALL_DIR}/.env"
    fi
else
    info "Config already exists at ${INSTALL_DIR}/config.yaml (not overwriting)"
fi

# ─── Install systemd services ───
info "Installing systemd services"

cat > /etc/systemd/system/attackmap-poller.service <<EOF
[Unit]
Description=BTAK Poller
After=network.target

[Service]
Type=simple
WorkingDirectory=${INSTALL_DIR}
EnvironmentFile=${INSTALL_DIR}/.env
ExecStart=/usr/bin/python3 ${INSTALL_DIR}/src/poller.py
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

cat > /etc/systemd/system/attackmap-http.service <<EOF
[Unit]
Description=BTAK HTTP Server
After=network.target

[Service]
Type=simple
WorkingDirectory=${INSTALL_DIR}
EnvironmentFile=${INSTALL_DIR}/.env
ExecStart=/usr/bin/python3 ${INSTALL_DIR}/src/server.py
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload

# ─── Health check ───
info "Running health check..."

checks_passed=0
checks_total=4

# Check 1: Config exists
if [ -f "${INSTALL_DIR}/config.yaml" ]; then
    info "  Config file: OK"
    checks_passed=$((checks_passed + 1))
else
    warn "  Config file: MISSING"
fi

# Check 2: Source files exist
if [ -f "${INSTALL_DIR}/src/poller.py" ] && [ -f "${INSTALL_DIR}/src/server.py" ]; then
    info "  Source files: OK"
    checks_passed=$((checks_passed + 1))
else
    warn "  Source files: MISSING"
fi

# Check 3: Frontend exists
if [ -f "${INSTALL_DIR}/static/index.html" ]; then
    info "  Frontend: OK"
    checks_passed=$((checks_passed + 1))
else
    warn "  Frontend: MISSING"
fi

# Check 4: Python can import yaml
if python3 -c "import yaml" 2>/dev/null; then
    info "  Python yaml: OK"
    checks_passed=$((checks_passed + 1))
else
    warn "  Python yaml: MISSING (pip install pyyaml)"
fi

echo ""
echo "=== Health Check: ${checks_passed}/${checks_total} passed ==="
echo ""

# ─── Final instructions ───
info "Installation complete!"
echo ""
echo "Next steps:"
echo "  1. Edit config:    nano ${INSTALL_DIR}/config.yaml"
echo "  2. Start poller:   systemctl start attackmap-poller"
echo "  3. Start server:   systemctl start attackmap-http"
echo "  4. Enable on boot: systemctl enable attackmap-poller attackmap-http"
echo "  5. View map:       http://<your-ip>/"
echo ""
echo "Useful commands:"
echo "  journalctl -u attackmap-poller -f    # Poller logs"
echo "  journalctl -u attackmap-http -f      # HTTP server logs"
echo "  curl -s http://localhost/clear        # Reset session"
echo "  curl -s http://localhost/archives     # List archived sessions"
echo "  cat ${INSTALL_DIR}/static/debug.json | python3 -m json.tool  # Debug state"
