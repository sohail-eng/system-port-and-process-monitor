#!/usr/bin/env bash
# Remove System Port & Process Monitor install artifacts.
# Usage: sudo ./deploy/uninstall.sh [--restore-backup]
set -euo pipefail

APP_NAME="port-dashboard"
APP_USER="port-dashboard"
INSTALL_ROOT="/opt/port-dashboard"
WEB_ROOT="/var/www/html"
HTPASSWD_FILE="/etc/nginx/port-dashboard.htpasswd"
NGINX_SITE_AVAILABLE="/etc/nginx/sites-available/default"
SERVICE_UNIT="/etc/systemd/system/port-dashboard.service"
CTL_BIN="/usr/local/sbin/port-dashboard-ctl"
CTL_SERVICE_UNIT="/etc/systemd/system/port-dashboard-ctl.service"
SUDOERS_FILE="/etc/sudoers.d/port-dashboard"
RESTORE=0

log() { printf '==> %s\n' "$*"; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

if [[ "${EUID}" -ne 0 ]]; then
  die "Run as root: sudo $0"
fi

for arg in "$@"; do
  case "${arg}" in
    --restore-backup) RESTORE=1 ;;
    -h|--help)
      echo "Usage: sudo $0 [--restore-backup]"
      exit 0
      ;;
    *) die "Unknown argument: ${arg}" ;;
  esac
done

log "Stopping and disabling ${APP_NAME}.service and port-dashboard-ctl.service"
systemctl stop "${APP_NAME}.service" 2>/dev/null || true
systemctl disable "${APP_NAME}.service" 2>/dev/null || true
systemctl stop port-dashboard-ctl.service 2>/dev/null || true
systemctl disable port-dashboard-ctl.service 2>/dev/null || true

if [[ -f "${SERVICE_UNIT}" ]]; then
  rm -f "${SERVICE_UNIT}"
  log "Removed ${SERVICE_UNIT}"
fi

if [[ -f "${CTL_SERVICE_UNIT}" ]]; then
  rm -f "${CTL_SERVICE_UNIT}"
  log "Removed ${CTL_SERVICE_UNIT}"
fi

systemctl daemon-reload

if [[ -d "${INSTALL_ROOT}" ]]; then
  rm -rf "${INSTALL_ROOT}"
  log "Removed ${INSTALL_ROOT}"
fi

if [[ -f "${HTPASSWD_FILE}" ]]; then
  rm -f "${HTPASSWD_FILE}"
  log "Removed ${HTPASSWD_FILE}"
fi

if [[ -f "${CTL_BIN}" ]]; then
  rm -f "${CTL_BIN}"
  log "Removed ${CTL_BIN}"
fi

if [[ -f "${SUDOERS_FILE}" ]]; then
  rm -f "${SUDOERS_FILE}"
  log "Removed ${SUDOERS_FILE}"
fi

if id -u "${APP_USER}" >/dev/null 2>&1; then
  userdel "${APP_USER}" 2>/dev/null || true
  log "Removed user ${APP_USER}"
fi

LATEST_BACKUP="$(ls -1dt /var/backups/${APP_NAME}-* 2>/dev/null | head -n1 || true)"

if [[ "${RESTORE}" -eq 1 ]]; then
  if [[ -z "${LATEST_BACKUP}" ]]; then
    die "No backup found under /var/backups/${APP_NAME}-*"
  fi
  log "Restoring from ${LATEST_BACKUP}"
  if [[ -f "${LATEST_BACKUP}/default" ]]; then
    cp -a "${LATEST_BACKUP}/default" "${NGINX_SITE_AVAILABLE}"
  fi
  if [[ -f "${LATEST_BACKUP}/index.html" ]]; then
    cp -a "${LATEST_BACKUP}/index.html" "${WEB_ROOT}/index.html"
  fi
  if nginx -t; then
    systemctl reload nginx
    log "Nginx config restored and reloaded"
  else
    die "Restored nginx config failed nginx -t"
  fi
else
  log "Leaving Nginx site and ${WEB_ROOT}/index.html in place"
  log "To restore the pre-install site: sudo $0 --restore-backup"
  if [[ -n "${LATEST_BACKUP}" ]]; then
    log "Latest backup: ${LATEST_BACKUP}"
  fi
fi

log "Uninstall finished"
