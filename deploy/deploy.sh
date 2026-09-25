#!/usr/bin/env bash
set -Eeuo pipefail

# SuperWall production deployment
# Usage:
#   sudo bash deploy/deploy.sh
#
# This script is intentionally idempotent:
# - updates the local git checkout to origin/main
# - installs required OS/.NET dependencies
# - creates/updates the service account and directories
# - backs up the database and current deployment
# - builds and publishes the dashboard
# - preserves /var/lib/superwall and the data symlink
# - installs the systemd unit
# - restarts and health-checks the dashboard

DOMAIN="superwall.hvmc.nl"
REPO_URL="https://github.com/Bendemen-Studios/SuperWall.git"
BRANCH="main"

APP_ROOT="/opt/superwall/current"
DATA_ROOT="/var/lib/superwall"
ENV_DIR="/etc/superwall"
ENV_FILE="$ENV_DIR/superwall.env"
BACKUP_ROOT="/var/backups/superwall"

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"

log() {
  echo
  echo "============================================================"
  echo " $*"
  echo "============================================================"
}

cleanup() {
  [[ -n "${WORKDIR:-}" && -d "$WORKDIR" ]] && rm -rf "$WORKDIR"
}
trap cleanup EXIT

on_error() {
  local line="$1"
  echo
  echo "ERROR: deployment failed at line $line."
  if systemctl list-unit-files superwall-dashboard.service >/dev/null 2>&1; then
    journalctl -u superwall-dashboard -n 80 --no-pager || true
  fi
  exit 1
}
trap 'on_error $LINENO' ERR

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Run this deploy script as root:"
  echo "  sudo bash deploy/deploy.sh"
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive

log "Updating SuperWall source"

if [[ ! -d "$REPO_ROOT/.git" ]]; then
  echo "Git repository not found at $REPO_ROOT"
  echo "Run this script from a cloned SuperWall repository."
  exit 1
fi

cd "$REPO_ROOT"
git config --global --add safe.directory "$REPO_ROOT" >/dev/null 2>&1 || true
git fetch --prune origin
git checkout "$BRANCH"
git pull --ff-only origin "$BRANCH"
git log -1 --oneline

log "Installing system dependencies"

apt-get update
apt-get install -y ca-certificates curl git openssl

if ! command -v dotnet >/dev/null 2>&1 || ! dotnet --list-sdks | grep -q '^8\.'; then
  install -d /etc/apt/keyrings
  if [[ ! -f /etc/apt/keyrings/microsoft.gpg ]]; then
    curl -fsSL https://packages.microsoft.com/keys/microsoft.asc |
      gpg --dearmor -o /etc/apt/keyrings/microsoft.gpg
    chmod a+r /etc/apt/keyrings/microsoft.gpg
  fi

  cat > /etc/apt/sources.list.d/microsoft-prod.list <<EOF
deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/microsoft.gpg] https://packages.microsoft.com/ubuntu/24.04/prod noble main
EOF

  apt-get update
  apt-get install -y dotnet-sdk-8.0
fi

log "Preparing SuperWall service account and directories"

getent group superwall >/dev/null || groupadd --system superwall
id superwall >/dev/null 2>&1 ||
  useradd --system --gid superwall --home /nonexistent --shell /usr/sbin/nologin superwall

install -d -o superwall -g superwall -m 0750 "$APP_ROOT"
install -d -o superwall -g superwall -m 0750 "$DATA_ROOT"
install -d -o root -g root -m 0750 "$ENV_DIR"
install -d -o root -g root -m 0750 "$BACKUP_ROOT"

log "Backing up current deployment"

TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
BACKUP_DIR="$BACKUP_ROOT/$TIMESTAMP"
mkdir -p "$BACKUP_DIR"

if [[ -f "$DATA_ROOT/superwall.db" ]]; then
  cp -a "$DATA_ROOT/superwall.db" "$BACKUP_DIR/superwall.db"
fi

if [[ -f "$ENV_FILE" ]]; then
  cp -a "$ENV_FILE" "$BACKUP_DIR/superwall.env"
fi

if [[ -d "$APP_ROOT" ]]; then
  tar -C "$APP_ROOT" --exclude='./data' -czf "$BACKUP_DIR/application.tar.gz" . || true
fi

# Keep the five most recent deployment backups.
mapfile -t OLD_BACKUPS < <(
  find "$BACKUP_ROOT" -mindepth 1 -maxdepth 1 -type d -printf '%T@ %p\n' |
  sort -nr |
  tail -n +6 |
  cut -d' ' -f2-
)
for backup in "${OLD_BACKUPS[@]}"; do
  [[ -n "$backup" ]] && rm -rf "$backup"
done

log "Stopping dashboard"

systemctl stop superwall-dashboard.service 2>/dev/null || true

log "Building dashboard"

WORKDIR="$(mktemp -d /tmp/superwall-deploy.XXXXXX)"

dotnet restore SuperWall.sln
dotnet publish src/SuperWall.Dashboard/SuperWall.Dashboard.csproj   -c Release   -r linux-x64   --self-contained false   -o "$WORKDIR/publish"

log "Deploying dashboard files"

# Never delete the persistent data symlink.
find "$APP_ROOT" -mindepth 1 -maxdepth 1 ! -name data -exec rm -rf -- {} +
cp -a "$WORKDIR/publish/." "$APP_ROOT/"
chown -R superwall:superwall "$APP_ROOT"

# Always recreate the persistent data link safely.
if [[ -L "$APP_ROOT/data" ]]; then
  rm -f "$APP_ROOT/data"
elif [[ -e "$APP_ROOT/data" ]]; then
  echo "ERROR: $APP_ROOT/data exists and is not a symlink. Refusing to delete persistent data."
  exit 1
fi
ln -s "$DATA_ROOT" "$APP_ROOT/data"
chown -h superwall:superwall "$APP_ROOT/data"

log "Preparing environment"

if [[ ! -f "$ENV_FILE" ]]; then
  ADMIN_PASSWORD="$(openssl rand -base64 36)"
  cat > "$ENV_FILE" <<EOF
SUPERWALL_BIND=http://0.0.0.0:7080
SUPERWALL_ALLOW_HTTP=1
SUPERWALL_ADMIN_PASSWORD=$ADMIN_PASSWORD
EOF
  chmod 600 "$ENV_FILE"
  echo "Created new dashboard credentials in $ENV_FILE"
else
  chmod 600 "$ENV_FILE"

  if grep -q '^SUPERWALL_BIND=' "$ENV_FILE"; then
    sed -i 's#^SUPERWALL_BIND=.*#SUPERWALL_BIND=http://0.0.0.0:7080#' "$ENV_FILE"
  else
    printf '\nSUPERWALL_BIND=http://0.0.0.0:7080\n' >> "$ENV_FILE"
  fi

  if grep -q '^SUPERWALL_ALLOW_HTTP=' "$ENV_FILE"; then
    sed -i 's#^SUPERWALL_ALLOW_HTTP=.*#SUPERWALL_ALLOW_HTTP=1#' "$ENV_FILE"
  else
    printf 'SUPERWALL_ALLOW_HTTP=1\n' >> "$ENV_FILE"
  fi
fi

chown root:root "$ENV_FILE"
chmod 600 "$ENV_FILE"

log "Installing systemd service"

install -m 0644 deploy/systemd/superwall-dashboard.service   /etc/systemd/system/superwall-dashboard.service

systemctl daemon-reload
systemctl enable superwall-dashboard.service

log "Starting dashboard"

systemctl start superwall-dashboard.service

if ! systemctl is-active --quiet superwall-dashboard.service; then
  echo "Dashboard failed to start."
  journalctl -u superwall-dashboard -n 100 --no-pager
  exit 1
fi

log "Running health checks"

for attempt in {1..20}; do
  if curl -fsS --max-time 3 http://127.0.0.1:7080/ >/dev/null 2>&1; then
    break
  fi

  if [[ "$attempt" -eq 20 ]]; then
    echo "Dashboard did not become ready on port 7080."
    journalctl -u superwall-dashboard -n 100 --no-pager
    exit 1
  fi

  sleep 1
done

echo
echo "SuperWall deployment complete."
echo "Commit: $(git rev-parse --short HEAD)"
echo "Backup: $BACKUP_DIR"
echo "Dashboard: https://$DOMAIN"
echo "Internal listener: http://0.0.0.0:7080"
echo "Environment: $ENV_FILE"
echo
systemctl --no-pager --full status superwall-dashboard.service | sed -n '1,12p'
