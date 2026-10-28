#!/usr/bin/env bash
# Install System Port & Process Monitor on Ubuntu (Nginx + systemd + FastAPI).
# Usage: sudo ./deploy/install.sh
set -euo pipefail

BACKEND_PORT=8009
APP_NAME="port-dashboard"
APP_USER="port-dashboard"
INSTALL_ROOT="/opt/port-dashboard"
WEB_ROOT="/var/www/html"
HTPASSWD_FILE="/etc/nginx/port-dashboard.htpasswd"
NGINX_SITE_AVAILABLE="/etc/nginx/sites-available/default"
NGINX_SITE_ENABLED="/etc/nginx/sites-enabled/default"
SERVICE_UNIT="/etc/systemd/system/port-dashboard.service"
CTL_BIN="/usr/local/sbin/port-dashboard-ctl"
CTL_SERVICE_UNIT="/etc/systemd/system/port-dashboard-ctl.service"
SUDOERS_FILE="/etc/sudoers.d/port-dashboard"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
BACKUP_DIR="/var/backups/${APP_NAME}-${TIMESTAMP}"

log() { printf '==> %s\n' "$*"; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

require_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    die "Run as root: sudo $0"
  fi
}

backup_path() {
  local src="$1"
  if [[ -e "${src}" ]]; then
    mkdir -p "${BACKUP_DIR}"
    cp -a "${src}" "${BACKUP_DIR}/"
    log "Backed up ${src} -> ${BACKUP_DIR}/"
  fi
}

install_packages() {
  log "Ensuring required packages are installed"
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get install -y \
    python3 \
    python3-venv \
    python3-pip \
    nginx \
    apache2-utils \
    iproute2 \
    curl
}

ensure_user() {
  if ! id -u "${APP_USER}" >/dev/null 2>&1; then
    log "Creating system user ${APP_USER}"
    useradd --system --home "${INSTALL_ROOT}" --shell /usr/sbin/nologin "${APP_USER}"
  else
    log "System user ${APP_USER} already exists"
  fi
}

install_app() {
  log "Installing application to ${INSTALL_ROOT}"
  mkdir -p "${INSTALL_ROOT}"
  rsync -a --delete \
    --exclude '.git' \
    --exclude 'venv' \
    --exclude '__pycache__' \
    --exclude '*.pyc' \
    --exclude '.venv' \
    "${PROJECT_ROOT}/" "${INSTALL_ROOT}/"

  if [[ ! -d "${INSTALL_ROOT}/venv" ]]; then
    python3 -m venv "${INSTALL_ROOT}/venv"
  fi
  # shellcheck disable=SC1091
  source "${INSTALL_ROOT}/venv/bin/activate"
  pip install --upgrade pip
  pip install -r "${INSTALL_ROOT}/requirements.txt"
  deactivate

  chown -R "${APP_USER}:${APP_USER}" "${INSTALL_ROOT}"
  chmod -R u=rwX,g=rX,o=rX "${INSTALL_ROOT}"
}

install_frontend() {
  log "Deploying frontend to ${WEB_ROOT}"
  mkdir -p "${WEB_ROOT}"
  backup_path "${WEB_ROOT}/index.html"
  if [[ -d "${WEB_ROOT}/assets" ]]; then
    backup_path "${WEB_ROOT}/assets"
  fi
  install -m 0644 "${PROJECT_ROOT}/frontend/index.html" "${WEB_ROOT}/index.html"
  if [[ -d "${PROJECT_ROOT}/frontend/assets" ]]; then
    mkdir -p "${WEB_ROOT}/assets"
    rsync -a "${PROJECT_ROOT}/frontend/assets/" "${WEB_ROOT}/assets/"
  fi
  chown -R root:www-data "${WEB_ROOT}"
  find "${WEB_ROOT}" -type d -exec chmod 755 {} \;
  find "${WEB_ROOT}" -type f -exec chmod 644 {} \;
}

install_control_helper() {
  log "Installing root control daemon (Unix socket helper)"
  backup_path "${CTL_SERVICE_UNIT}"
  # Keep CLI helper for manual/debug use; primary path is ctl_server.py
  backup_path "${CTL_BIN}"
  install -m 0755 "${SCRIPT_DIR}/port-dashboard-ctl" "${CTL_BIN}"
  chown root:root "${CTL_BIN}"
  install -m 0755 "${SCRIPT_DIR}/ctl_server.py" "${INSTALL_ROOT}/deploy/ctl_server.py"
  chown root:root "${INSTALL_ROOT}/deploy/ctl_server.py"

  install -m 0644 "${SCRIPT_DIR}/port-dashboard-ctl.service" "${CTL_SERVICE_UNIT}"

  # Remove legacy sudoers drop-in if present (no longer required)
  if [[ -f "${SUDOERS_FILE}" ]]; then
    backup_path "${SUDOERS_FILE}"
    rm -f "${SUDOERS_FILE}"
    log "Removed legacy ${SUDOERS_FILE}"
  fi

  systemctl daemon-reload
  systemctl enable port-dashboard-ctl.service
  systemctl restart port-dashboard-ctl.service
  sleep 0.5
  if [[ ! -S /run/port-dashboard/ctl.sock ]]; then
    systemctl --no-pager --full status port-dashboard-ctl.service || true
    die "Control socket /run/port-dashboard/ctl.sock was not created"
  fi
  # Ensure API user can connect
  chgrp port-dashboard /run/port-dashboard /run/port-dashboard/ctl.sock 2>/dev/null || true
  chmod 750 /run/port-dashboard
  chmod 660 /run/port-dashboard/ctl.sock
  log "Control daemon ready at /run/port-dashboard/ctl.sock"
}

install_systemd() {
  log "Installing API systemd unit"
  backup_path "${SERVICE_UNIT}"
  install -m 0644 "${SCRIPT_DIR}/port-dashboard.service" "${SERVICE_UNIT}"
  systemctl daemon-reload
  systemctl enable "${APP_NAME}.service"
  systemctl restart "${APP_NAME}.service"
}

wait_for_backend() {
  local i
  for i in $(seq 1 20); do
    if curl -fsS "http://127.0.0.1:${BACKEND_PORT}/api/health" >/dev/null 2>&1; then
      log "Backend healthy on 127.0.0.1:${BACKEND_PORT}"
      return 0
    fi
    sleep 0.5
  done
  systemctl --no-pager --full status "${APP_NAME}.service" || true
  die "Backend did not become healthy on 127.0.0.1:${BACKEND_PORT}"
}

verify_loopback_only() {
  if ss -ltn | awk '{print $4}' | grep -E "(^|:)0\\.0\\.0\\.0:${BACKEND_PORT}$|(^|:)\\[::\\]:${BACKEND_PORT}$|(^|:)\\*:${BACKEND_PORT}$" >/dev/null; then
    die "Backend appears to be listening on a public interface — aborting"
  fi
  if ! ss -ltn | awk '{print $4}' | grep -E "127\\.0\\.0\\.1:${BACKEND_PORT}$" >/dev/null; then
    die "Backend is not listening on 127.0.0.1:${BACKEND_PORT}"
  fi
  log "Confirmed backend listens only on 127.0.0.1:${BACKEND_PORT}"
}

configure_htpasswd() {
  if [[ -f "${HTPASSWD_FILE}" ]]; then
    log "Auth file already exists at ${HTPASSWD_FILE} (leaving unchanged)"
    chmod 640 "${HTPASSWD_FILE}"
    chown root:www-data "${HTPASSWD_FILE}"
    return 0
  fi

  log "Creating HTTP Basic Auth credentials"
  echo "Choose a username and a strong password for the dashboard."
  echo "The password will not be printed."
  local username
  read -r -p "Dashboard username [admin]: " username
  username="${username:-admin}"
  if [[ ! "${username}" =~ ^[A-Za-z0-9._@-]+$ ]]; then
    die "Invalid username"
  fi

  htpasswd -c "${HTPASSWD_FILE}" "${username}"
  chmod 640 "${HTPASSWD_FILE}"
  chown root:www-data "${HTPASSWD_FILE}"
  log "Wrote ${HTPASSWD_FILE} (mode 640, root:www-data)"
}

configure_nginx() {
  log "Configuring Nginx"
  backup_path "${NGINX_SITE_AVAILABLE}"
  install -m 0644 "${SCRIPT_DIR}/nginx-port-dashboard.conf" "${NGINX_SITE_AVAILABLE}"

  # Ensure default site is enabled exactly once
  ln -sfn "${NGINX_SITE_AVAILABLE}" "${NGINX_SITE_ENABLED}"

  if ! nginx -t; then
    die "nginx -t failed — previous configs are in ${BACKUP_DIR}"
  fi
  systemctl reload nginx
  log "Nginx reloaded"
}

print_summary() {
  cat <<EOF

============================================================
 Installation complete
============================================================
 Backup directory : ${BACKUP_DIR}
 App install      : ${INSTALL_ROOT}
 Frontend         : ${WEB_ROOT}/index.html
 Backend (local)  : http://127.0.0.1:${BACKEND_PORT}/api/health
 Dashboard URL    : http://127.0.0.1/   (HTTP Basic Auth)
 Auth file        : ${HTPASSWD_FILE}
 Service          : ${APP_NAME}.service
 Control daemon   : port-dashboard-ctl.service
 Control socket   : /run/port-dashboard/ctl.sock

 Quick checks:
   systemctl status ${APP_NAME} --no-pager
   curl -sS http://127.0.0.1:${BACKEND_PORT}/api/health
   curl -I http://127.0.0.1/          # expect 401
   curl -u USER:PASS -I http://127.0.0.1/   # expect 200

 LocalTunnel is NOT modified. To expose Nginx (port 80) instead
 of another app, see README.md.
============================================================
EOF
}

main() {
  require_root
  [[ -f "${PROJECT_ROOT}/backend/app.py" ]] || die "Run from the project tree (missing backend/app.py)"
  [[ -f "${PROJECT_ROOT}/frontend/index.html" ]] || die "Missing frontend/index.html"
  command -v rsync >/dev/null || apt-get install -y rsync

  install_packages
  ensure_user
  install_app
  install_frontend
  install_control_helper
  install_systemd
  wait_for_backend
  verify_loopback_only
  configure_htpasswd
  configure_nginx
  print_summary
}

main "$@"
