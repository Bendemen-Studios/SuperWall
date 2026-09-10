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
apt-get install -y ca-certificates curl git openssl

if ! command -v dotnet >/dev/null 2>&1 || ! dotnet --list-sdks | grep -q '^8\.'; then
  install -d /etc/apt/keyrings
  curl -fsSL https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor -o /etc/apt/keyrings/microsoft.gpg
  chmod a+r /etc/apt/keyrings/microsoft.gpg
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/microsoft.gpg] https://packages.microsoft.com/ubuntu/24.04/prod noble main" > /etc/apt/sources.list.d/microsoft-prod.list
  apt-get update
  apt-get install -y dotnet-sdk-8.0
fi

getent group superwall >/dev/null || groupadd --system superwall
id superwall >/dev/null 2>&1 || useradd --system --gid superwall --home /nonexistent --shell /usr/sbin/nologin superwall

install -d -o superwall -g superwall -m 0750 "$APP_ROOT" "$DATA_ROOT"
install -d -o root -g root -m 0750 "$ENV_DIR"

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
SUPERWALL_BIND=http://0.0.0.0:7080
SUPERWALL_ALLOW_HTTP=1
SUPERWALL_ADMIN_PASSWORD=$ADMIN_PASSWORD
SUPERWALL_ENROLLMENT_KEY=$ENROLLMENT_KEY
EOF
  chmod 600 "$ENV_DIR/superwall.env"
  echo "Generated new dashboard credentials in $ENV_DIR/superwall.env"
else
  chmod 600 "$ENV_DIR/superwall.env"
  sed -i 's#^SUPERWALL_BIND=.*#SUPERWALL_BIND=http://0.0.0.0:7080#' "$ENV_DIR/superwall.env"
fi

# Persist dashboard data outside the deployed application directory.
ln -sfn "$DATA_ROOT" "$APP_ROOT/data"

install -m 0644 deploy/systemd/superwall-dashboard.service /etc/systemd/system/superwall-dashboard.service

systemctl daemon-reload
systemctl enable superwall-dashboard
systemctl restart superwall-dashboard

if ! systemctl is-active --quiet superwall-dashboard; then
  echo "SuperWall dashboard failed to start. Recent logs:"
  journalctl -u superwall-dashboard -n 80 --no-pager || true
  exit 1
fi

echo
echo "SuperWall dashboard deployment complete."
echo "Public URL (via Nginx Proxy Manager): https://$DOMAIN"
echo "Dashboard listener: http://0.0.0.0:7080"
echo "Environment: $ENV_DIR/superwall.env"
echo "Nginx Proxy Manager must forward $DOMAIN to this VPS on port 7080."
