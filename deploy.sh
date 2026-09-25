#!/usr/bin/env bash
set -Eeuo pipefail

# SuperWall Dashboard deployment
# Run as root from /opt/superwall-source or with sudo.
#
# What this script does:
# 1. Fetches and fast-forwards main
# 2. Builds the Dashboard
# 3. Verifies the publish output BEFORE stopping the service
# 4. Backs up the current deployment and database
# 5. Deploys while preserving /opt/superwall/current/data
# 6. Restarts the service
# 7. Verifies the service and HTTPS endpoint
# 8. Rolls back automatically when the new service cannot start

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_DIR="${SOURCE_DIR:-$SCRIPT_DIR}"
PUBLISH_DIR="${PUBLISH_DIR:-/opt/superwall-publish}"
CURRENT_DIR="${CURRENT_DIR:-/opt/superwall/current}"
DATA_DIR="${DATA_DIR:-/var/lib/superwall}"
SERVICE="${SERVICE:-superwall-dashboard}"
HEALTH_URL="${HEALTH_URL:-https://superwall.hvmc.nl}"
BACKUP_ROOT="${BACKUP_ROOT:-/opt/superwall/backups}"
BRANCH="${BRANCH:-main}"

timestamp() { date '+%Y%m%d-%H%M%S'; }
log() { printf '\n[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*"; }
die() { printf '\nERROR: %s\n' "$*" >&2; exit 1; }

if [[ "$(id -u)" -ne 0 ]]; then
    die "Run this script as root: sudo bash deploy.sh"
fi

export DEBIAN_FRONTEND=noninteractive

if ! command -v git >/dev/null || ! command -v curl >/dev/null || ! command -v gpg >/dev/null; then
    apt-get update
    apt-get install -y ca-certificates curl git gnupg
fi

if ! command -v dotnet >/dev/null || ! dotnet --list-sdks 2>/dev/null | grep -q '^8\.'; then
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

command -v systemctl >/dev/null || die "systemd is not available."

if [[ ! -d "$SOURCE_DIR/.git" ]]; then
    die "Git repository not found: $SOURCE_DIR"
fi

[[ -f "$SOURCE_DIR/src/SuperWall.Dashboard/SuperWall.Dashboard.csproj" ]] ||
    die "Dashboard project not found."

cd "$SOURCE_DIR"

log "Current commit"
git log -1 --oneline || true

log "Fetching origin/$BRANCH"
git fetch origin "$BRANCH"

log "Updating source tree"
git checkout "$BRANCH"
git pull --ff-only origin "$BRANCH"

COMMIT="$(git rev-parse --short HEAD)"
FULL_COMMIT="$(git rev-parse HEAD)"
log "Deploying commit $COMMIT"

log "Building Dashboard"
rm -rf "$PUBLISH_DIR"
dotnet restore src/SuperWall.Dashboard/SuperWall.Dashboard.csproj
dotnet publish src/SuperWall.Dashboard/SuperWall.Dashboard.csproj \
    -c Release \
    -o "$PUBLISH_DIR"

[[ -f "$PUBLISH_DIR/SuperWall.Dashboard.dll" ]] ||
    die "Publish failed: SuperWall.Dashboard.dll was not created."

[[ -f "$PUBLISH_DIR/SuperWall.Dashboard.deps.json" ]] ||
    die "Publish output is incomplete."

[[ -f "$PUBLISH_DIR/SuperWall.Dashboard.runtimeconfig.json" ]] ||
    die "Publish output is incomplete."

log "Build successful"
du -sh "$PUBLISH_DIR"

# Create backup BEFORE touching the running deployment.
BACKUP_DIR="$BACKUP_ROOT/$(timestamp)-$COMMIT"
mkdir -p "$BACKUP_ROOT"

if [[ -d "$CURRENT_DIR" ]]; then
    log "Backing up current deployment to $BACKUP_DIR"
    cp -a "$CURRENT_DIR" "$BACKUP_DIR"
fi

DB_BACKUP=""
if [[ -f "$DATA_DIR/superwall.db" ]]; then
    mkdir -p "$BACKUP_DIR"
    DB_BACKUP="$BACKUP_DIR/superwall.db"
    log "Backing up database to $DB_BACKUP"
    cp -a "$DATA_DIR/superwall.db" "$DB_BACKUP"
fi

# Remember whether data was a symlink before deployment.
DATA_LINK_TARGET=""
if [[ -L "$CURRENT_DIR/data" ]]; then
    DATA_LINK_TARGET="$(readlink "$CURRENT_DIR/data")"
fi

log "Stopping $SERVICE"
systemctl stop "$SERVICE"

rollback() {
    local rc=$?
    trap - ERR
    printf '\nDeployment failed (exit %s). Attempting rollback...\n' "$rc" >&2

    systemctl stop "$SERVICE" >/dev/null 2>&1 || true

    if [[ -d "$BACKUP_DIR" ]]; then
        rm -rf "$CURRENT_DIR"
        cp -a "$BACKUP_DIR" "$CURRENT_DIR"
        chown -R root:root "$CURRENT_DIR" || true
        systemctl start "$SERVICE" >/dev/null 2>&1 || true
        sleep 2
        systemctl --no-pager --full status "$SERVICE" || true
        echo "Rollback restored: $BACKUP_DIR" >&2
    else
        echo "No deployment backup was available." >&2
    fi

    exit "$rc"
}
trap rollback ERR

log "Preparing deployment directory"
mkdir -p "$CURRENT_DIR"

# Delete only application files. Never delete the persistent data directory.
find "$CURRENT_DIR" -mindepth 1 -maxdepth 1 ! -name data -exec rm -rf {} +

log "Copying published Dashboard"
cp -a "$PUBLISH_DIR"/. "$CURRENT_DIR"/

# Recreate the persistent data link only when it was missing.
if [[ ! -e "$CURRENT_DIR/data" ]]; then
    mkdir -p "$DATA_DIR"
    ln -s "$DATA_DIR" "$CURRENT_DIR/data"
elif [[ -L "$CURRENT_DIR/data" ]]; then
    :
elif [[ -d "$CURRENT_DIR/data" ]]; then
    log "Existing data directory detected; preserving it."
else
    die "Unexpected /opt/superwall/current/data state."
fi

chown -R root:root "$CURRENT_DIR"

# Install/update the systemd unit from the repository before starting.
install -m 0644 "$SOURCE_DIR/deploy/systemd/superwall-dashboard.service"     "/etc/systemd/system/superwall-dashboard.service"

# Make absolutely sure the database still exists when one existed before.
if [[ -n "$DB_BACKUP" && ! -f "$DATA_DIR/superwall.db" ]]; then
    log "Database disappeared unexpectedly; restoring database backup."
    cp -a "$DB_BACKUP" "$DATA_DIR/superwall.db"
fi

log "Starting $SERVICE"
systemctl daemon-reload
systemctl enable "$SERVICE"
systemctl start "$SERVICE"

sleep 3

log "Checking systemd service"
systemctl is-active --quiet "$SERVICE" ||
    die "$SERVICE is not active."

log "Checking service status"
systemctl --no-pager --full status "$SERVICE"

log "Checking HTTPS endpoint"
if command -v curl >/dev/null; then
    curl --fail --silent --show-error --max-time 15 "$HEALTH_URL" >/dev/null ||
        die "HTTPS health check failed: $HEALTH_URL"
    log "HTTPS health check OK: $HEALTH_URL"
else
    log "curl is not installed; HTTPS check skipped."
fi

trap - ERR

log "Deployment successful"
echo
echo "Commit:  $FULL_COMMIT"
echo "Backup:  $BACKUP_DIR"
[[ -n "$DB_BACKUP" ]] && echo "DB backup: $DB_BACKUP"
echo "Service: $SERVICE"
echo "URL:     $HEALTH_URL"
echo
echo "Recent logs:"
journalctl -u "$SERVICE" -n 30 --no-pager
