#!/usr/bin/env bash
# =============================================================================
# NIDS Agent — Installation Script
# Supports: Debian/Ubuntu Linux (tested on 20.04+, 22.04+)
# Requires root (for Scapy raw socket capture + iptables).
# =============================================================================
set -euo pipefail

INSTALL_DIR="/opt/nids/agent"
ENV_FILE="/etc/nids/agent.env"
SERVICE_FILE="/etc/systemd/system/nids-agent.service"
VENV="$INSTALL_DIR/venv"

echo "============================================="
echo "  NIDS Agent Installation"
echo "============================================="

# --- 1. System dependencies ---
echo "[1/6] Installing system packages..."
apt-get update -qq
apt-get install -y -qq python3 python3-pip python3-venv \
    tcpdump libpcap-dev iptables curl

# --- 2. Copy files ---
echo "[2/6] Copying agent files to $INSTALL_DIR..."
mkdir -p "$INSTALL_DIR"
cp -r agent/ "$INSTALL_DIR/"
chmod -R 750 "$INSTALL_DIR"

# --- 3. Python venv ---
echo "[3/6] Creating Python venv..."
python3 -m venv "$VENV"
"$VENV/bin/pip" install --upgrade pip -q
"$VENV/bin/pip" install -r "$INSTALL_DIR/agent/requirements.txt" -q

# --- 4. Register with server ---
echo "[4/6] Registering agent with server..."
mkdir -p /etc/nids

read -rp "Enter NIDS Server URL (e.g. http://192.168.1.100:5000): " SERVER_URL
read -rp "Enter Agent Name (alphanumeric, hyphens allowed): "          AGENT_NAME
read -rp "Enter Registration Key: "                                     REG_KEY
read -rp "Enter Network Interface to capture (leave blank for auto): " IFACE

RESP=$(curl -sf -X POST "${SERVER_URL}/api/register" \
    -H "Content-Type: application/json" \
    -d "{\"agent_name\":\"${AGENT_NAME}\",\"registration_key\":\"${REG_KEY}\"}" || true)

if [[ -z "$RESP" ]]; then
    echo "ERROR: Failed to contact server at ${SERVER_URL}. Check URL and registration key." >&2
    exit 1
fi

TOKEN=$(echo "$RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('token',''))")
if [[ -z "$TOKEN" ]]; then
    echo "ERROR: Server did not return a token. Response: $RESP" >&2
    exit 1
fi

echo "  -> Registered successfully. Token obtained."

# --- 5. Environment file ---
echo "[5/6] Writing environment file to $ENV_FILE..."

cat > "$ENV_FILE" << EOF
SERVER_URL=${SERVER_URL}
AGENT_NAME=${AGENT_NAME}
AGENT_TOKEN=${TOKEN}
INTERFACE=${IFACE}
OFFLINE_QUEUE_FILE=${INSTALL_DIR}/offline_queue.jsonl
EOF

chmod 640 "$ENV_FILE"
echo "  -> Environment saved to $ENV_FILE"

# --- 6. systemd service ---
echo "[6/6] Installing systemd service..."
cat > "$SERVICE_FILE" << EOF
[Unit]
Description=NIDS Agent (${AGENT_NAME})
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=${INSTALL_DIR}/agent
EnvironmentFile=${ENV_FILE}
ExecStart=${VENV}/bin/python agent.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=nids-agent

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable nids-agent
systemctl start nids-agent

echo ""
echo "============================================="
echo "  Agent installation complete!"
echo "  Service: systemctl status nids-agent"
echo "  Logs:    journalctl -u nids-agent -f"
echo "============================================="
