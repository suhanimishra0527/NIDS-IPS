#!/usr/bin/env bash
# =============================================================================
# NIDS Central Server — Installation Script
# Supports: Debian/Ubuntu Linux (tested on 20.04+, 22.04+)
# Run as root or with sudo.
# =============================================================================
set -euo pipefail

INSTALL_DIR="/opt/nids/server"
ENV_FILE="/etc/nids/server.env"
SERVICE_FILE="/etc/systemd/system/nids-server.service"
VENV="$INSTALL_DIR/venv"

echo "============================================="
echo "  NIDS Server Installation"
echo "============================================="

# --- 1. System dependencies ---
echo "[1/7] Installing system packages..."
apt-get update -qq
apt-get install -y -qq python3 python3-pip python3-venv \
    postgresql postgresql-contrib redis-server libpq-dev

# --- 2. Create directory and copy files ---
echo "[2/7] Copying server files to $INSTALL_DIR..."
mkdir -p "$INSTALL_DIR"
cp -r server/ "$INSTALL_DIR/"
chmod -R 750 "$INSTALL_DIR"

# --- 3. Python virtual environment ---
echo "[3/7] Creating Python venv..."
python3 -m venv "$VENV"
"$VENV/bin/pip" install --upgrade pip -q
"$VENV/bin/pip" install -r "$INSTALL_DIR/server/requirements.txt" -q

# --- 4. PostgreSQL setup ---
echo "[4/7] Configuring PostgreSQL..."
read -rp "Enter PostgreSQL password for 'nids_user': " DB_PASS
systemctl enable postgresql --now

sudo -u postgres psql -c "CREATE USER nids_user WITH PASSWORD '$DB_PASS';" 2>/dev/null || true
sudo -u postgres psql -c "CREATE DATABASE nids_db OWNER nids_user;" 2>/dev/null || true
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE nids_db TO nids_user;" 2>/dev/null || true

# --- 5. Redis ---
echo "[5/7] Enabling Redis..."
systemctl enable redis-server --now

# --- 6. Environment file ---
echo "[6/7] Writing environment file to $ENV_FILE..."
mkdir -p /etc/nids

read -rp "Enter JWT secret (leave blank for auto-generated): " JWT_SECRET
if [[ -z "$JWT_SECRET" ]]; then
    JWT_SECRET=$(python3 -c "import secrets; print(secrets.token_hex(32))")
fi

read -rp "Enter agent registration key [default: changeme]: " REG_KEY
REG_KEY="${REG_KEY:-changeme}"

SERVER_PORT=5000
read -rp "Enter server port [default: 5000]: " INPUT_PORT
SERVER_PORT="${INPUT_PORT:-5000}"

cat > "$ENV_FILE" << EOF
DATABASE_URL=postgresql://nids_user:${DB_PASS}@localhost:5432/nids_db
REDIS_URL=redis://localhost:6379/0
JWT_SECRET=${JWT_SECRET}
AGENT_REGISTRATION_KEY=${REG_KEY}
PORT=${SERVER_PORT}
HOST=0.0.0.0
DEBUG=false
EOF

chmod 640 "$ENV_FILE"
echo "  -> Environment saved to $ENV_FILE"

# --- 7. systemd service ---
echo "[7/7] Installing systemd service..."
cat > "$SERVICE_FILE" << EOF
[Unit]
Description=NIDS Central Server
After=network.target postgresql.service redis.service
Requires=postgresql.service redis.service

[Service]
Type=simple
User=root
WorkingDirectory=${INSTALL_DIR}/server
EnvironmentFile=${ENV_FILE}
ExecStart=${VENV}/bin/python app.py
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=nids-server

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable nids-server
systemctl start nids-server

echo ""
echo "============================================="
echo "  Installation complete!"
echo "  Service: systemctl status nids-server"
echo "  Logs:    journalctl -u nids-server -f"
echo "  Dashboard: http://<server-ip>:${SERVER_PORT}/"
echo "  Registration key: ${REG_KEY}"
echo "============================================="
