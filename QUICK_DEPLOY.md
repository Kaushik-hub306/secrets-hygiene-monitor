#!/bin/bash
# ============================================================
# Secrets Hygiene Monitor -- Quick Deploy
# ============================================================
# Copy this entire script and paste it in your VPS terminal.
# Tested on Ubuntu 24.04.
# ============================================================

set -euo pipefail

echo ""
echo "============================================"
echo " Secrets Hygiene Monitor -- Deploy"
echo "============================================"
echo ""

# ---- Step 1: Update system ----
echo "[1/6] Updating system packages..."
sudo apt-get update -qq
sudo apt-get install -y -qq python3.12 python3.12-venv python3-pip git nginx sqlite3 curl jq

# ---- Step 2: Install Gitleaks ----
echo "[2/6] Installing Gitleaks..."
if ! command -v gitleaks &>/dev/null; then
    curl -sL https://github.com/gitleaks/gitleaks/releases/download/v8.18.4/gitleaks_8.18.4_linux_x64.tar.gz \
        -o /tmp/gitleaks.tar.gz
    sudo tar -xz -C /usr/local/bin -f /tmp/gitleaks.tar.gz gitleaks
    sudo chmod +x /usr/local/bin/gitleaks
    rm -f /tmp/gitleaks.tar.gz
    echo "  Installed: $(gitleaks version)"
else
    echo "  Already installed"
fi

# ---- Step 3: Setup app directory ----
echo "[3/6] Setting up application..."
APP_DIR="/opt/secrets-monitor"
DATA_DIR="$APP_DIR/data"

sudo mkdir -p "$APP_DIR" "$DATA_DIR"

# Clone or update
if [ -d "$APP_DIR/api" ]; then
    echo "  Updating existing installation..."
    cd "$APP_DIR" && sudo git pull origin main
else
    echo "  Cloning from GitHub..."
    sudo git clone https://github.com/Kaushik-hub306/secrets-hygiene-monitor.git "$APP_DIR"
fi

sudo chown -R ubuntu:ubuntu "$APP_DIR"

# ---- Step 4: Python dependencies ----
echo "[4/6] Installing Python dependencies..."
python3.12 -m venv "$APP_DIR/venv"
"$APP_DIR/venv/bin/pip" install --upgrade pip -q
"$APP_DIR/venv/bin/pip" install -r "$APP_DIR/requirements.txt" -q

# ---- Step 5: Environment file ----
echo "[5/6] Configuring environment..."
if [ ! -f "$APP_DIR/.env" ]; then
    cp "$APP_DIR/.env.example" "$APP_DIR/.env"

    # Generate random secrets
    WEBHOOK_SECRET=$(openssl rand -hex 32)
    sed -i "s|GITHUB_WEBHOOK_SECRET=|GITHUB_WEBHOOK_SECRET=$WEBHOOK_SECRET|" "$APP_DIR/.env"
    sed -i "s|APP_ENV=development|APP_ENV=production|" "$APP_DIR/.env"
    sed -i "s|HOST=127.0.0.1|HOST=0.0.0.0|" "$APP_DIR/.env"
    sed -i "s|DATABASE_PATH=.*|DATABASE_PATH=$DATA_DIR/secrets_monitor.db|" "$APP_DIR/.env"

    chmod 600 "$APP_DIR/.env"

    echo ""
    echo "  >>> IMPORTANT: You MUST edit $APP_DIR/.env"
    echo "      Set these values:"
    echo "        GITHUB_CLIENT_ID=your_github_oauth_app_id"
    echo "        GITHUB_CLIENT_SECRET=your_github_oauth_app_secret"
    echo ""
    echo "      To create a GitHub OAuth App:"
    echo "        1. Go to https://github.com/settings/developers"
    echo "        2. Click 'New OAuth App'"
    echo "        3. Set callback URL to: http://YOUR_SERVER_IP:8000/auth/github/callback"
    echo ""
    read -p "  Press Enter after you've noted this down..."
else
    echo "  .env already exists."
fi

# ---- Step 6: Create systemd service ----
echo "[6/6] Creating auto-start service..."

sudo tee /etc/systemd/system/secrets-monitor.service > /dev/null <<'EOF'
[Unit]
Description=Secrets Hygiene Monitor
After=network.target

[Service]
Type=simple
User=ubuntu
Group=ubuntu
WorkingDirectory=/opt/secrets-monitor
Environment=PATH=/opt/secrets-monitor/venv/bin:/usr/local/bin:/usr/bin:/bin
EnvironmentFile=/opt/secrets-monitor/.env
ExecStart=/opt/secrets-monitor/venv/bin/python3 run.py
Restart=always
RestartSec=10
StandardOutput=append:/var/log/secrets-monitor.log
StandardError=append:/var/log/secrets-monitor.log

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable secrets-monitor

# ---- Done ----
echo ""
echo "============================================"
echo " Deploy complete!"
echo "============================================"
echo ""
echo "  Next steps BEFORE starting the server:"
echo ""
echo "  1. Create a GitHub OAuth App:"
echo "     https://github.com/settings/developers"
echo "     - Homepage URL: http://$(curl -s ifconfig.me):8000"
echo "     - Callback URL: http://$(curl -s ifconfig.me):8000/auth/github/callback"
echo ""
echo "  2. Edit your .env file:"
echo "     nano $APP_DIR/.env"
echo "     Set GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET"
echo ""
echo "  3. Start the server:"
echo "     sudo systemctl start secrets-monitor"
echo ""
echo "  4. Check it's running:"
echo "     sudo systemctl status secrets-monitor"
echo "     tail -f /var/log/secrets-monitor.log"
echo ""
echo "  5. Open in browser:"
echo "     http://$(curl -s ifconfig.me):8000"
echo ""
