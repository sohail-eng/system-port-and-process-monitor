# System Port & Process Monitor

Production-conscious Ubuntu dashboard for inspecting listening TCP/UDP sockets, owning processes, and related systemd units.

- **Frontend:** HTML, CSS, and vanilla JavaScript (no CDN)
- **Backend:** FastAPI + Uvicorn (loopback only)
- **Edge:** Nginx static hosting + reverse proxy + HTTP Basic Auth
- **Service:** systemd unit with capability-based process inspection

## Architecture

```text
Browser / LocalTunnel
        |
        v
   Nginx :80
   (HTTP Basic Auth)
        |
        +-- /            -> /var/www/html (dashboard)
        |
        +-- /api/*       -> 127.0.0.1:8009 (FastAPI)
```

The API never binds to a public interface. Authentication is enforced at Nginx for both the UI and the API.

## Features

- Summary cards derived from live API data (not hardcoded)
- Listening TCP/UDP table with address, state, process, PID, executable, systemd unit, and unit status
- Instant search and TCP/UDP filters
- Manual Refresh only (no polling)
- Browser-local favorites (hearts) sorted first
- Tabs: **Ports** | **systemd** | **Docker** | **PM2**
- Guarded runtime actions with typed confirmation (stop/start/restart/kill as appropriate)
- Loading, last-updated, error, and empty-result states
- XSS-safe rendering via `textContent`

## Repository layout

```text
ports-dashboard/
  backend/app.py
  frontend/index.html
  deploy/
    install.sh
    uninstall.sh
    nginx-port-dashboard.conf
    port-dashboard.service
    port-dashboard-ctl
    port-dashboard.sudoers
  requirements.txt
  README.md
```

## Security model

| Control | Detail |
| --- | --- |
| Bind address | Uvicorn listens on `127.0.0.1:8009` only |
| Auth | Nginx `auth_basic` + `/etc/nginx/port-dashboard.htpasswd` (mode `640`, `root:www-data`) |
| Privileges | Dedicated `port-dashboard` user with `CAP_SYS_PTRACE` + `CAP_DAC_READ_SEARCH` for inspection |
| Process control | Root daemon `port-dashboard-ctl.service` via Unix socket `/run/port-dashboard/ctl.sock` (no sudo from the API) |
| Deny extras | Stop/start of `user@*.service` is blocked (whole session); PID **Kill** is still allowed for stuck apps under that session (e.g. daphne). Hard units (nginx/ssh/…) block kill too. |
| API surface | `/api/health`, `/api/ports`, `/api/system`, plus guarded `POST` stop/restart/kill |
| Confirmations | Client must type exact unit name or PID; server re-checks |
| Deny-list | Refuses actions on nginx, ssh/sshd, dbus, NetworkManager, systemd-*, port-dashboard, PID 1, and related comm names |
| Secrets | No env vars, cmdline args, or credentials returned by the API |
| CORS | Not enabled |
| Firewall | Install does not modify UFW/firewalld |

**Privilege tradeoff:** inspection uses ambient capabilities; destructive actions go through a root-owned helper with a hard deny-list. The API stays on loopback behind Nginx Basic Auth. Do not expose port `8009` publicly.

## Prerequisites

- Ubuntu with `sudo`
- Nginx (installed by the script if missing)
- Python 3.10+
- Tools: `ss` (iproute2), `systemctl`, `htpasswd` (apache2-utils)

## Quick deploy

From the project root:

```bash
chmod +x deploy/install.sh deploy/uninstall.sh
sudo ./deploy/install.sh
```

The installer will:

1. Back up touched files under `/var/backups/port-dashboard-<timestamp>/`
2. Install packages (`python3-venv`, Nginx, apache2-utils, …)
3. Create user `port-dashboard` and install the app to `/opt/port-dashboard`
4. Create a virtualenv and install Python dependencies
5. Deploy the frontend to `/var/www/html` (after backing up the previous `index.html`)
6. Install and start `port-dashboard-ctl.service` (root helper + `/run/port-dashboard/ctl.sock`)
7. Enable and start `port-dashboard.service` on `127.0.0.1:8009`
8. Prompt for a dashboard username/password if the htpasswd file does not exist
9. Install the Nginx site, run `nginx -t`, and reload Nginx

The password prompt uses `htpasswd` interactively and is never echoed by the script.

## Manual deploy (mirror of the script)

Useful when you need to adapt paths or review each step.

```bash
# 1) Packages
sudo apt-get update
sudo apt-get install -y python3 python3-venv python3-pip nginx apache2-utils iproute2 curl rsync

# 2) User + app tree
sudo useradd --system --home /opt/port-dashboard --shell /usr/sbin/nologin port-dashboard || true
sudo mkdir -p /opt/port-dashboard
sudo rsync -a --exclude .git --exclude venv ./ /opt/port-dashboard/
sudo python3 -m venv /opt/port-dashboard/venv
sudo /opt/port-dashboard/venv/bin/pip install -r /opt/port-dashboard/requirements.txt
sudo chown -R port-dashboard:port-dashboard /opt/port-dashboard

# 3) Frontend (backup first)
sudo cp -a /var/www/html/index.html /var/www/html/index.html.bak.$(date +%F) || true
sudo install -m 0644 frontend/index.html /var/www/html/index.html

# 4) Guarded control helper (stop / restart / kill)
sudo install -m 0755 deploy/port-dashboard-ctl /usr/local/sbin/port-dashboard-ctl
sudo install -m 0440 deploy/port-dashboard.sudoers /etc/sudoers.d/port-dashboard
sudo visudo -cf /etc/sudoers.d/port-dashboard

# 5) systemd
sudo install -m 0644 deploy/port-dashboard.service /etc/systemd/system/port-dashboard.service
sudo systemctl daemon-reload
sudo systemctl enable --now port-dashboard.service

# 6) Auth (outside web root)
sudo htpasswd -c /etc/nginx/port-dashboard.htpasswd admin   # omit -c to add users later
sudo chmod 640 /etc/nginx/port-dashboard.htpasswd
sudo chown root:www-data /etc/nginx/port-dashboard.htpasswd

# 7) Nginx
sudo cp /etc/nginx/sites-available/default /etc/nginx/sites-available/default.bak.$(date +%F)
sudo install -m 0644 deploy/nginx-port-dashboard.conf /etc/nginx/sites-available/default
sudo nginx -t && sudo systemctl reload nginx
```

## Local development (no Nginx)

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn backend.app:app --host 127.0.0.1 --port 8009 --reload
```

In another terminal, serve the frontend or open `frontend/index.html` only after pointing API calls appropriately. For a quick check of the API:

```bash
curl -sS http://127.0.0.1:8009/api/health
curl -sS http://127.0.0.1:8009/api/ports | head
curl -sS http://127.0.0.1:8009/api/system
```

## Verification checklist

```bash
systemctl status port-dashboard --no-pager
ss -ltnp | grep 8009          # should show 127.0.0.1:8009 only
curl -sS http://127.0.0.1:8009/api/health
curl -I http://127.0.0.1/     # expect HTTP 401
curl -u 'USER:PASS' -I http://127.0.0.1/          # expect HTTP 200
curl -u 'USER:PASS' -sS http://127.0.0.1/api/ports | head
sudo nginx -t
journalctl -u port-dashboard -n 50 --no-pager
```

Acceptance expectations:

- Service is `active (running)`
- `/api/ports` returns real TCP and UDP listeners
- Unauthenticated HTTP requests receive `401`
- Authenticated homepage returns `200` and renders live data
- Search filters by port, PID, process, service, etc.
- Refresh fetches new data without a full page reload; no auto-refresh
- Unrelated services (Postgres, Redis, Speak2Talk, Docker, …) remain untouched

## LocalTunnel (optional)

This project **does not** modify any LocalTunnel unit by default.

On hosts where a tunnel already points at another app (for example Speak2Talk on port `8000`), leave it alone unless you intentionally want the public tunnel to reach this dashboard.

To expose **Nginx (port 80)** — and therefore the authenticated dashboard — update the tunnel command to `--port 80` while keeping your existing subdomain, for example:

```bash
lt --port 80 --subdomain <your-subdomain>
```

Or edit the systemd unit’s `ExecStart` accordingly, then:

```bash
sudo systemctl daemon-reload
sudo systemctl restart localtunnel.service
```

Never expose the FastAPI port `8009` through LocalTunnel. Always tunnel to Nginx so Basic Auth remains in front.

## API reference

### `GET /api/health`

```json
{ "status": "ok", "service": "System Port & Process Monitor", "timestamp": "..." }
```

### `GET /api/ports`

Returns `summary`, `ports[]`, optional `warnings`, and timing metadata. Each port row includes:

`port`, `protocol`, `address`, `state`, `process_name`, `pid`, `executable`, `service`, `service_status`

Missing process/service fields use `"unavailable"` / `null` placeholders.

### `GET /api/system`

Hostname, uptime, load average, and memory figures from `/proc`.

### `POST /api/service/stop` / `POST /api/service/start` / `POST /api/service/restart`

```json
{ "unit": "ollama.service", "confirm": "ollama.service" }
```

`confirm` must exactly equal `unit`. Protected units are rejected.

### `POST /api/services/status`

```json
{ "units": ["ollama.service", "redis-server.service"] }
```

Returns ActiveState for each unit so the Services tab can keep showing stopped units.

### `POST /api/process/kill`

```json
{ "pid": 7288, "confirm": "7288" }
```

`confirm` must equal the PID string. If the PID maps to a non-protected systemd unit, the API returns `409` and asks you to use Stop/Restart instead. Kill sends `SIGTERM`, then `SIGKILL` if the process is still alive after a short wait.

## Process control UX

- Ports tab: **Stop/Restart** when a unit is known; otherwise **Kill** when a PID is known
- Services tab: units from listening sockets **plus** previously seen units (browser-local), with live status
- Inactive units show **Start**; active units show **Stop/Restart**
- Modal requires typing the unit name or PID before Confirm
- Hearts / known-service list remain browser-local

## Uninstall

```bash
sudo ./deploy/uninstall.sh
```

Restore the previous Nginx site and homepage from the latest backup:

```bash
sudo ./deploy/uninstall.sh --restore-backup
```

## Limitations

- Process ownership for foreign UIDs needs the ambient capabilities configured in the unit; without them many system daemons show as unavailable
- Mapping PID → systemd unit uses cgroup metadata and can miss non-service processes, containers, or transient scopes
- Executable paths may be unavailable under tight `/proc` permissions
- UDP sockets often show state `UNCONN` (normal for listening UDP)
- Containerized listeners may appear as the runtime (for example `docker-proxy`) rather than the inner process
- Protected units (nginx, ssh, systemd core, the dashboard itself, …) cannot be stopped/restarted/killed from the UI
- Stop/Restart/Kill require the control helper + sudoers installed by `deploy/install.sh`
- There is no “start arbitrary unit” action for services that are not already visible via listening sockets

## License

Use and adapt freely in your environment. Review security controls before exposing anything beyond localhost or a trusted tunnel.
