#!/usr/bin/env bash
set -euo pipefail

DOMAIN="superwall.hvmc.nl"
APP_ROOT="/opt/superwall/current"
DATA_ROOT="/var/lib/superwall"
ENV_DIR="/etc/superwall"
REPO="https://github.com/Bendemen-Studios/SuperWall.git"

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Run this installer as root."
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y ca-certificates curl git nginx certbot python3-certbot-nginx openssl gnupg

if ! command -v dotnet >/dev/null 2>&1 || ! dotnet --list-sdks | grep -q '^8\.'; then
  install -d /etc/apt/keyrings
  curl -fsSL https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor --yes -o /etc/apt/keyrings/microsoft.gpg
  chmod a+r /etc/apt/keyrings/microsoft.gpg
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/microsoft.gpg] https://packages.microsoft.com/ubuntu/24.04/prod noble main" > /etc/apt/sources.list.d/microsoft-prod.list
  apt-get update
  apt-get install -y dotnet-sdk-8.0
fi

getent group superwall >/dev/null || groupadd --system superwall
id superwall >/dev/null 2>&1 || useradd --system --gid superwall --home /nonexistent --shell /usr/sbin/nologin superwall

install -d -o superwall -g superwall -m 0750 "$APP_ROOT" "$DATA_ROOT"
install -d -o root -g root -m 0750 "$ENV_DIR"
install -d -o root -g root -m 0755 /var/www/certbot

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

git clone --depth 1 "$REPO" "$WORKDIR/repo"
cd "$WORKDIR/repo"

dotnet restore SuperWall.sln
dotnet publish src/SuperWall.Dashboard/SuperWall.Dashboard.csproj -c Release -r linux-x64 --self-contained false -o "$WORKDIR/publish"

rm -rf "$APP_ROOT"/*
cp -a "$WORKDIR/publish"/. "$APP_ROOT"/
chown -R superwall:superwall "$APP_ROOT" "$DATA_ROOT"

if [[ ! -f "$ENV_DIR/superwall.env" ]]; then
  ADMIN_PASSWORD="$(openssl rand -base64 36)"
  ENROLLMENT_KEY="$(openssl rand -base64 48)"
  cat > "$ENV_DIR/superwall.env" <<EOF
SUPERWALL_BIND=http://127.0.0.1:7080
SUPERWALL_ALLOW_HTTP=1
SUPERWALL_ADMIN_PASSWORD=$ADMIN_PASSWORD
SUPERWALL_ENROLLMENT_KEY=$ENROLLMENT_KEY
EOF
  chmod 600 "$ENV_DIR/superwall.env"
  echo "Generated new dashboard credentials in $ENV_DIR/superwall.env"
else
  chmod 600 "$ENV_DIR/superwall.env"
fi

# Persist dashboard database outside the application deployment directory.
ln -sfn "$DATA_ROOT" "$APP_ROOT/data"

install -m 0644 deploy/systemd/superwall-dashboard.service /etc/systemd/system/superwall-dashboard.service
rm -f /etc/nginx/sites-enabled/default

# First configure Nginx as HTTP-only so nginx -t succeeds before a certificate exists.
cat > /etc/nginx/sites-available/superwall.hvmc.nl.conf <<'NGINX_BOOTSTRAP'
server {
    listen 80;
    listen [::]:80;
    server_name superwall.hvmc.nl;

    location /.well-known/acme-challenge/ {
        root /var/www/certbot;
    }

    location / {
        proxy_pass http://127.0.0.1:7080;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto http;
        proxy_set_header X-Forwarded-Host $host;
        proxy_set_header Connection "";
    }
}
NGINX_BOOTSTRAP

ln -sfn /etc/nginx/sites-available/superwall.hvmc.nl.conf /etc/nginx/sites-enabled/superwall.hvmc.nl.conf
nginx -t
systemctl daemon-reload
systemctl enable --now superwall-dashboard
systemctl enable --now nginx

if ! getent ahosts "$DOMAIN" >/dev/null 2>&1; then
  echo "DNS for $DOMAIN does not resolve yet. Point it to this server, then run:"
  echo "  certbot --nginx -d $DOMAIN --redirect"
  systemctl --no-pager --full status superwall-dashboard || true
  exit 0
fi

certbot certonly --webroot -w /var/www/certbot -d "$DOMAIN" --non-interactive --agree-tos --register-unsafely-without-email

# Replace bootstrap HTTP config with the production HTTPS config from the repository.
install -m 0644 "$WORKDIR/repo/deploy/nginx/superwall.hvmc.nl.conf" /etc/nginx/sites-available/superwall.hvmc.nl.conf
nginx -t
systemctl reload nginx

# Test certificate renewal configuration without changing the live certificate.
certbot renew --dry-run

systemctl --no-pager --full status superwall-dashboard || true

echo
echo "SuperWall dashboard deployment complete."
echo "URL: https://$DOMAIN"
echo "Internal dashboard: http://127.0.0.1:7080"
echo "Environment: $ENV_DIR/superwall.env"
