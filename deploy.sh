#!/bin/bash
# ============================================================
# Secrets Hygiene Monitor -- VPS Deployment Script
# ============================================================
# Run this on your Ubuntu 24.04 VPS.
# It sets up: Python venv, Gitleaks, nginx, systemd service
# 
# Usage: bash deploy.sh
# ============================================================

set -euo pipefail

APP_DIR="/opt/secrets-monitor"
APP_USER="secrets-monitor"
VENV_DIR="$APP_DIR/venv"
DATA_DIR="$APP_DIR/data"
LOG_DIR="/var/log/secrets-monitor"

echo "============================================"
echo " Secrets Hygiene Monitor -- VPS Deploy"
echo "============================================"

# ---- Step 1: System dependencies ----
echo ""
echo "[1/8] Installing system dependencies..."
sudo apt-get update -qq
sudo apt-get install -y -qq \
    python3.12 \
    python3.12-venv \
    python3-pip \
    git \
    nginx \
    sqlite3 \
    curl \
    jq

# ---- Step 2: Create app user ----
echo ""
echo "[2/8] Creating app user..."
if ! id "$APP_USER" &>/dev/null; then
    sudo useradd --system --home "$APP_DIR" --shell /usr/sbin/nologin "$APP_USER"
    echo "  Created user: $APP_USER"
else
    echo "  User already exists: $APP_USER"
fi

# ---- Step 3: Install Gitleaks ----
echo ""
echo "[3/8] Installing Gitleaks..."
if ! command -v gitleaks &>/dev/null; then
    # Pin to a specific version for reproducibility
    GITLEAKS_VERSION="v8.18.4"
    echo "  Downloading ${GITLEAKS_VERSION}..."
    curl -sL "https://github.com/gitleaks/gitleaks/releases/download/${GITLEAKS_VERSION}/gitleaks_8.18.4_linux_x64.tar.gz" \
        -o /tmp/gitleaks.tar.gz
    sudo tar -xz -C /usr/local/bin -f /tmp/gitleaks.tar.gz gitleaks
    sudo chmod +x /usr/local/bin/gitleaks
    rm -f /tmp/gitleaks.tar.gz
    echo "  Installed: $(gitleaks version)"
else
    echo "  Already installed: $(gitleaks version)"
fi

# ---- Step 4: Setup app directory ----
echo ""
echo "[4/8] Setting up application directory..."
sudo mkdir -p "$APP_DIR" "$DATA_DIR" "$LOG_DIR"
sudo chown -R "$APP_USER:$APP_USER" "$APP_DIR" "$LOG_DIR"

# Copy app files (assumes you've cloned the repo to /tmp/secrets-hygiene-monitor)
if [ -d "/tmp/secrets-hygiene-monitor" ]; then
    echo "  Copying files from /tmp/secrets-hygiene-monitor..."
    sudo cp -r /tmp/secrets-hygiene-monitor/* "$APP_DIR/"
elif [ -d "$APP_DIR/api" ]; then
    echo "  App directory already exists, skipping copy."
    echo "  (Update files manually or re-clone the repo)"
else
    echo "  Cloning from GitHub..."
    sudo -u "$APP_USER" git clone \
        https://github.com/Kaushik-hub306/secrets-hygiene-monitor.git \
        "$APP_DIR"
fi

sudo chown -R "$APP_USER:$APP_USER" "$APP_DIR"

# ---- Step 5: Python virtual environment ----
echo ""
echo "[5/8] Setting up Python virtual environment..."
sudo -u "$APP_USER" python3.12 -m venv "$VENV_DIR"
sudo -u "$APP_USER" "$VENV_DIR/bin/pip" install --upgrade pip -q
sudo -u "$APP_USER" "$VENV_DIR/bin/pip" install -r "$APP_DIR/requirements.txt" -q
echo "  Dependencies installed."

# ---- Step 6: Environment file ----
echo ""
echo "[6/8] Configuring environment..."
if [ ! -f "$APP_DIR/.env" ]; then
    echo "  Creating .env file (YOU MUST EDIT THIS)..."
    sudo -u "$APP_USER" cp "$APP_DIR/.env.example" "$APP_DIR/.env"
    sudo -u "$APP_USER" chmod 600 "$APP_DIR/.env"
    
    # Generate random webhook secret
    WEBHOOK_SECRET=$(openssl rand -hex 32)
    sudo -u "$APP_USER" sed -i "s|GITHUB_WEBHOOK_SECRET=|GITHUB_WEBHOOK_SECRET=$WEBHOOK_SECRET|" "$APP_DIR/.env"
    
    # Set app env to production
    sudo -u "$APP_USER" sed -i "s|APP_ENV=development|APP_ENV=production|" "$APP_DIR/.env"
    
    # Bind to 0.0.0.0 (behind nginx)
    sudo -u "$APP_USER" sed -i "s|HOST=127.0.0.1|HOST=0.0.0.0|" "$APP_DIR/.env"
    
    # Set database path
    sudo -u "$APP_USER" sed -i "s|DATABASE_PATH=.*|DATABASE_PATH=$DATA_DIR/secrets_monitor.db|" "$APP_DIR/.env"
    
    echo ""
    echo "  >>> IMPORTANT: Edit $APP_DIR/.env and set:"
    echo "      GITHUB_CLIENT_ID=your_client_id"
    echo "      GITHUB_CLIENT_SECRET=your_client_secret"
    echo ""
else
    echo "  .env already exists, skipping."
fi

# ---- Step 7: Systemd service ----
echo ""
echo "[7/8] Creating systemd service..."
sudo tee /etc/systemd/system/secrets-monitor.service > /dev/null <<EOF
[Unit]
Description=Secrets Hygiene Monitor
After=network.target

[Service]
Type=simple
User=$APP_USER
Group=$APP_USER
WorkingDirectory=$APP_DIR
Environment=PATH=$VENV_DIR/bin:/usr/local/bin:/usr/bin:/bin
EnvironmentFile=$APP_DIR/.env
ExecStart=$VENV_DIR/bin/python3 run.py
Restart=always
RestartSec=10
StandardOutput=append:$LOG_DIR/app.log
StandardError=append:$LOG_DIR/app.log

# Hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$DATA_DIR $LOG_DIR /tmp
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable secrets-monitor
sudo systemctl restart secrets-monitor
echo "  Service started."

# ---- Step 8: Nginx reverse proxy ----
echo ""
echo "[8/8] Configuring nginx..."

# Ask for domain/IP
read -p "  Enter your domain or IP address (e.g. secrets.yourdomain.com): " DOMAIN_NAME

sudo tee /etc/nginx/sites-available/secrets-monitor > /dev/null <<EOF
server {
    listen 80;
    server_name $DOMAIN_NAME;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_read_timeout 300;
    }
}
EOF

sudo ln -sf /etc/nginx/sites-available/secrets-monitor /etc/nginx/sites-enabled/
# Remove default site only if it exists (safe)
if [ -L /etc/nginx/sites-enabled/default ]; then
    sudo rm /etc/nginx/sites-enabled/default
fi
sudo nginx -t && sudo systemctl restart nginx
echo "  Nginx configured for $DOMAIN_NAME"

# ---- Done ----
echo ""
echo "============================================"
echo " Deployment complete!"
echo "============================================"
echo ""
echo " Next steps:"
echo "  1. Edit $APP_DIR/.env with your GitHub OAuth credentials"
echo "  2. Set up SSL: sudo certbot --nginx -d $DOMAIN_NAME"
echo "  3. Open $DOMAIN_NAME in your browser"
echo ""
echo " Useful commands:"
echo "  Check status:  sudo systemctl status secrets-monitor"
echo "  View logs:     tail -f $LOG_DIR/app.log"
echo "  Restart:       sudo systemctl restart secrets-monitor"
echo "  Update code:   sudo -u $APP_USER git -C $APP_DIR pull && sudo systemctl restart secrets-monitor"
echo ""
