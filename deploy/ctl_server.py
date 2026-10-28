#!/usr/bin/env python3
"""
Root control daemon for System Port & Process Monitor.

Unix socket commands:
  stop|start|restart <unit.service>
  kill|killforce <pid>
  docker-list
  docker-start|docker-stop|docker-restart <id-or-name>
  pm2-list
  pm2-start|pm2-stop|pm2-restart|pm2-delete <id-or-name>
  ping
"""

from __future__ import annotations

import json
import os
import pwd
import re
import select
import signal
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

SOCKET_PATH = "/run/port-dashboard/ctl.sock"
UNIT_RE = re.compile(r"^[A-Za-z0-9@_.\\-]+\.service$")
DOCKER_REF_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
PM2_REF_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")

PROTECTED_UNITS = frozenset(
    {
        "port-dashboard.service",
        "port-dashboard-ctl.service",
        "nginx.service",
        "ssh.service",
        "sshd.service",
        "dbus.service",
        "dbus-broker.service",
        "NetworkManager.service",
        "systemd-logind.service",
        "systemd-journald.service",
        "systemd-resolved.service",
        "systemd-networkd.service",
        "systemd-udevd.service",
        "systemd-timesyncd.service",
    }
)

PROTECTED_COMM = frozenset(
    {
        "systemd",
        "init",
        "sshd",
        "ssh",
        "nginx",
        "port-dashboard",
        "uvicorn",
        "dbus-daemon",
        "NetworkManager",
    }
)

DOCKER_BIN_CANDIDATES = (
    "/usr/bin/docker",
    "/usr/local/bin/docker",
    "/bin/docker",
)
PM2_BIN_CANDIDATES = (
    "/usr/local/bin/pm2",
    "/usr/bin/pm2",
)


def _reply(conn: socket.socket, ok: bool, message: str) -> None:
    status = "OK" if ok else "ERR"
    # Keep payload on one line for the simple protocol
    safe = message.replace("\n", " ").replace("\r", " ")
    conn.sendall(f"{status} {safe}\n".encode("utf-8", errors="replace"))


def _reply_json(conn: socket.socket, ok: bool, payload: object) -> None:
    body = json.dumps(payload, separators=(",", ":"), ensure_ascii=True)
    _reply(conn, ok, body)


def _unit_protected(unit: str) -> bool:
    if unit in PROTECTED_UNITS:
        return True
    if unit.startswith("systemd-"):
        return True
    if unit.startswith("user@") and unit.endswith(".service"):
        return True
    return False


def _validate_unit(unit: str) -> str | None:
    if not UNIT_RE.fullmatch(unit):
        return "invalid unit name"
    if _unit_protected(unit):
        return "unit is protected"
    return None


def _validate_pid(pid_s: str) -> tuple[int | None, str | None]:
    if not pid_s.isdigit():
        return None, "invalid pid"
    pid = int(pid_s)
    if pid < 2:
        return None, "pid not allowed"
    if not Path(f"/proc/{pid}").is_dir():
        return None, "process not found"
    try:
        comm = Path(f"/proc/{pid}/comm").read_text(encoding="utf-8").strip()
    except OSError:
        return None, "process not found"
    if comm in PROTECTED_COMM:
        return None, "process is protected"
    return pid, None


def _run(
    args: list[str],
    timeout: float = 30.0,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    base_env = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/bin", "LC_ALL": "C"}
    if env:
        base_env.update(env)
    return subprocess.run(
        args,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
        shell=False,
        env=base_env,
    )


def _which(candidates: tuple[str, ...]) -> str | None:
    for path in candidates:
        if Path(path).is_file() and os.access(path, os.X_OK):
            return path
    return None


def _docker_bin() -> str | None:
    return _which(DOCKER_BIN_CANDIDATES)


def _pm2_bin() -> str | None:
    found = _which(PM2_BIN_CANDIDATES)
    if found:
        return found
    # nvm installs
    for path in sorted(Path("/home").glob("*/.nvm/versions/node/*/bin/pm2")):
        if path.is_file() and os.access(path, os.X_OK):
            return str(path)
    return None


def _pm2_home_and_user() -> tuple[str | None, str | None]:
    explicit = os.environ.get("PORT_DASHBOARD_PM2_HOME")
    if explicit and Path(explicit).is_dir():
        return explicit, os.environ.get("PORT_DASHBOARD_PM2_USER")
    for home in sorted(Path("/home").iterdir()):
        pm2_home = home / ".pm2"
        if pm2_home.is_dir():
            return str(pm2_home), home.name
    return None, None


def handle_stop(unit: str) -> tuple[bool, str]:
    err = _validate_unit(unit)
    if err:
        return False, err
    try:
        result = _run(["systemctl", "stop", unit])
    except (OSError, subprocess.TimeoutExpired):
        return False, "systemctl stop failed"
    if result.returncode != 0:
        return False, (result.stderr or result.stdout or "systemctl stop failed").strip()[:200]
    return True, f"stopped {unit}"


def handle_start(unit: str) -> tuple[bool, str]:
    err = _validate_unit(unit)
    if err:
        return False, err
    try:
        result = _run(["systemctl", "start", unit])
    except (OSError, subprocess.TimeoutExpired):
        return False, "systemctl start failed"
    if result.returncode != 0:
        return False, (result.stderr or result.stdout or "systemctl start failed").strip()[:200]
    return True, f"started {unit}"


def handle_restart(unit: str) -> tuple[bool, str]:
    err = _validate_unit(unit)
    if err:
        return False, err
    try:
        result = _run(["systemctl", "restart", unit])
    except (OSError, subprocess.TimeoutExpired):
        return False, "systemctl restart failed"
    if result.returncode != 0:
        return False, (result.stderr or result.stdout or "systemctl restart failed").strip()[:200]
    return True, f"restarted {unit}"


def handle_kill(pid_s: str, force: bool = False) -> tuple[bool, str]:
    pid, err = _validate_pid(pid_s)
    if err or pid is None:
        return False, err or "invalid pid"

    if force:
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            return True, f"process {pid} already exited"
        except PermissionError:
            return False, "permission denied"
        except OSError:
            return False, "failed to force-kill process"
        return True, f"force-killed {pid}"

    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        return True, f"process {pid} already exited"
    except PermissionError:
        return False, "permission denied"
    except OSError:
        return False, "failed to signal process"

    for _ in range(10):
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return True, f"killed {pid}"
        time.sleep(0.2)

    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        return True, f"killed {pid}"
    except OSError:
        return False, "failed to force-kill process"
    return True, f"killed {pid}"


def _docker_env() -> dict[str, str]:
    env: dict[str, str] = {}
    # Prefer classic engine socket; fall back to Docker Desktop user socket.
    for sock in (
        "/var/run/docker.sock",
        "/run/docker.sock",
    ):
        if Path(sock).exists():
            env["DOCKER_HOST"] = f"unix://{sock}"
            return env
    for sock in sorted(Path("/home").glob("*/.docker/desktop/docker.sock")):
        if sock.exists():
            env["DOCKER_HOST"] = f"unix://{sock}"
            return env
    return env


def handle_docker_list() -> tuple[bool, object]:
    docker = _docker_bin()
    if not docker:
        return False, {"error": "docker binary not found", "containers": []}
    try:
        result = _run(
            [
                docker,
                "ps",
                "-a",
                "--format",
                "{{json .}}",
            ],
            timeout=20.0,
            env=_docker_env(),
        )
    except (OSError, subprocess.TimeoutExpired):
        return False, {"error": "docker ps failed", "containers": []}
    if result.returncode != 0:
        err = (result.stderr or result.stdout or "docker unavailable").strip()[:200]
        return False, {"error": err, "containers": []}

    containers = []
    for line in (result.stdout or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        containers.append(
            {
                "id": (row.get("ID") or row.get("Id") or "")[:12],
                "name": (row.get("Names") or row.get("Name") or "").lstrip("/"),
                "image": row.get("Image") or "",
                "status": row.get("Status") or "",
                "state": row.get("State") or "",
                "ports": row.get("Ports") or "",
            }
        )
    return True, {"containers": containers, "error": None}


def handle_docker_action(action: str, ref: str) -> tuple[bool, str]:
    if not DOCKER_REF_RE.fullmatch(ref):
        return False, "invalid container reference"
    docker = _docker_bin()
    if not docker:
        return False, "docker binary not found"
    try:
        result = _run([docker, action, ref], timeout=60.0, env=_docker_env())
    except (OSError, subprocess.TimeoutExpired):
        return False, f"docker {action} failed"
    if result.returncode != 0:
        return False, (result.stderr or result.stdout or f"docker {action} failed").strip()[:200]
    return True, f"docker {action} {ref}"


def handle_pm2_list() -> tuple[bool, object]:
    pm2 = _pm2_bin()
    pm2_home, pm2_user = _pm2_home_and_user()
    if not pm2:
        return False, {"error": "pm2 binary not found", "processes": [], "user": pm2_user}
    if not pm2_home:
        return False, {"error": "no PM2 home found under /home", "processes": [], "user": None}

    env = {"PM2_HOME": pm2_home}
    args = [pm2, "jlist"]
    # Prefer running as the owning user so the daemon matches their session
    if pm2_user:
        try:
            pwd.getpwnam(pm2_user)
            args = ["runuser", "-u", pm2_user, "--", pm2, "jlist"]
        except KeyError:
            pass

    try:
        result = _run(args, timeout=20.0, env=env)
    except (OSError, subprocess.TimeoutExpired):
        return False, {"error": "pm2 jlist failed", "processes": [], "user": pm2_user}
    if result.returncode != 0:
        err = (result.stderr or result.stdout or "pm2 unavailable").strip()[:200]
        return False, {"error": err, "processes": [], "user": pm2_user}

    raw = (result.stdout or "").strip()
    if not raw:
        return True, {"processes": [], "error": None, "user": pm2_user}
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return False, {"error": "invalid pm2 json", "processes": [], "user": pm2_user}

    processes = []
    if isinstance(data, list):
        for row in data:
            if not isinstance(row, dict):
                continue
            env_pm2 = row.get("pm2_env") or {}
            processes.append(
                {
                    "id": row.get("pm_id"),
                    "name": row.get("name") or "",
                    "pid": env_pm2.get("pm_pid") or row.get("pid"),
                    "status": env_pm2.get("status") or "",
                    "restarts": env_pm2.get("restart_time"),
                    "mode": env_pm2.get("exec_mode") or "",
                    "cwd": env_pm2.get("pm_cwd") or "",
                    "script": env_pm2.get("pm_exec_path") or "",
                    "memory": (row.get("monit") or {}).get("memory"),
                    "cpu": (row.get("monit") or {}).get("cpu"),
                }
            )
    return True, {"processes": processes, "error": None, "user": pm2_user}


def _build_log_command(kind: str, target: str) -> tuple[list[str] | None, dict[str, str] | None, str | None]:
    """Return (argv, env, error)."""
    if kind == "systemd":
        if not UNIT_RE.fullmatch(target):
            return None, None, "invalid unit name"
        return (
            [
                "journalctl",
                "-u",
                target,
                "-n",
                "150",
                "-f",
                "--no-pager",
                "-o",
                "cat",
            ],
            None,
            None,
        )

    if kind == "docker":
        if not DOCKER_REF_RE.fullmatch(target):
            return None, None, "invalid container reference"
        docker = _docker_bin()
        if not docker:
            return None, None, "docker binary not found"
        env = _docker_env()
        return [docker, "logs", "-f", "--tail", "150", target], env, None

    if kind == "pm2":
        if not PM2_REF_RE.fullmatch(target):
            return None, None, "invalid pm2 reference"
        pm2 = _pm2_bin()
        pm2_home, pm2_user = _pm2_home_and_user()
        if not pm2:
            return None, None, "pm2 binary not found"
        if not pm2_home:
            return None, None, "no PM2 home found"
        env = {"PM2_HOME": pm2_home}
        args = [pm2, "logs", target, "--lines", "150", "--raw"]
        if pm2_user:
            try:
                pwd.getpwnam(pm2_user)
                args = ["runuser", "-u", pm2_user, "--", pm2, "logs", target, "--lines", "150", "--raw"]
            except KeyError:
                pass
        return args, env, None

    return None, None, "invalid log kind"


def stream_logs(conn: socket.socket, kind: str, target: str) -> None:
    """Stream live logs to the client as lines: L <text>\\n until END."""
    argv, env, err = _build_log_command(kind, target)
    if err or not argv:
        _reply(conn, False, err or "invalid log request")
        return

    base_env = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/bin", "LC_ALL": "C"}
    if env:
        base_env.update(env)

    try:
        proc = subprocess.Popen(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=False,
            bufsize=0,
            env=base_env,
        )
    except OSError:
        _reply(conn, False, "failed to start log stream")
        return

    conn.sendall(b"OK STREAM\n")
    assert proc.stdout is not None
    pending = b""
    try:
        while True:
            rlist, _, _ = select.select([proc.stdout, conn], [], [], 1.0)
            if conn in rlist:
                try:
                    peek = conn.recv(1, socket.MSG_DONTWAIT)
                except BlockingIOError:
                    peek = b"\0"
                except OSError:
                    break
                if not peek:
                    break
            if proc.stdout in rlist:
                chunk = proc.stdout.read(4096)
                if not chunk:
                    break
                pending += chunk
                while b"\n" in pending:
                    raw_line, pending = pending.split(b"\n", 1)
                    safe = raw_line.decode("utf-8", errors="replace").replace("\r", "")
                    try:
                        conn.sendall(("L " + safe + "\n").encode("utf-8", errors="replace"))
                    except OSError:
                        return
            elif proc.poll() is not None:
                if pending:
                    safe = pending.decode("utf-8", errors="replace").replace("\r", "")
                    try:
                        conn.sendall(("L " + safe + "\n").encode("utf-8", errors="replace"))
                    except OSError:
                        return
                    pending = b""
                break
    finally:
        try:
            proc.send_signal(signal.SIGTERM)
        except OSError:
            pass
        try:
            proc.wait(timeout=2)
        except Exception:
            try:
                proc.kill()
            except OSError:
                pass
        try:
            conn.sendall(b"END\n")
        except OSError:
            pass


def handle_pm2_action(action: str, ref: str) -> tuple[bool, str]:
    if not PM2_REF_RE.fullmatch(ref):
        return False, "invalid pm2 reference"
    if action not in ("start", "stop", "restart", "delete"):
        return False, "invalid pm2 action"
    pm2 = _pm2_bin()
    pm2_home, pm2_user = _pm2_home_and_user()
    if not pm2:
        return False, "pm2 binary not found"
    if not pm2_home:
        return False, "no PM2 home found"

    env = {"PM2_HOME": pm2_home}
    args = [pm2, action, ref]
    if pm2_user:
        try:
            pwd.getpwnam(pm2_user)
            args = ["runuser", "-u", pm2_user, "--", pm2, action, ref]
        except KeyError:
            pass

    try:
        result = _run(args, timeout=60.0, env=env)
    except (OSError, subprocess.TimeoutExpired):
        return False, f"pm2 {action} failed"
    if result.returncode != 0:
        return False, (result.stderr or result.stdout or f"pm2 {action} failed").strip()[:200]
    return True, f"pm2 {action} {ref}"


def handle_line(line: str) -> tuple[bool, str | object]:
    parts = line.strip().split()
    if not parts:
        return False, "empty command"
    action = parts[0].lower()

    if action in ("stop", "start", "restart") and len(parts) == 2:
        if action == "stop":
            return handle_stop(parts[1])
        if action == "start":
            return handle_start(parts[1])
        return handle_restart(parts[1])
    if action == "kill" and len(parts) == 2:
        return handle_kill(parts[1], force=False)
    if action == "killforce" and len(parts) == 2:
        return handle_kill(parts[1], force=True)

    if action == "docker-list" and len(parts) == 1:
        # Always OK so the API can render an empty/unavailable state
        _ok, payload = handle_docker_list()
        return True, payload
    if action in ("docker-start", "docker-stop", "docker-restart") and len(parts) == 2:
        docker_action = action.split("-", 1)[1]
        return handle_docker_action(docker_action, parts[1])

    if action == "pm2-list" and len(parts) == 1:
        _ok, payload = handle_pm2_list()
        return True, payload
    if action in ("pm2-start", "pm2-stop", "pm2-restart", "pm2-delete") and len(parts) == 2:
        pm2_action = action.split("-", 1)[1]
        return handle_pm2_action(pm2_action, parts[1])

    if action == "ping":
        return True, "pong"
    return (
        False,
        "usage: stop|start|restart <unit> | kill|killforce <pid> | "
        "docker-list | docker-start|stop|restart <ref> | "
        "pm2-list | pm2-start|stop|restart|delete <ref> | "
        "logs-systemd|logs-docker|logs-pm2 <target> | ping",
    )


def _handle_client(conn: socket.socket) -> None:
    """Serve one client connection. Log streams may block for a long time."""
    try:
        conn.settimeout(90.0)
        data = b""
        while b"\n" not in data and len(data) < 1024:
            chunk = conn.recv(256)
            if not chunk:
                break
            data += chunk
        line = data.decode("utf-8", errors="replace").split("\n", 1)[0]
        parts = line.strip().split()
        if len(parts) == 2 and parts[0] in ("logs-systemd", "logs-docker", "logs-pm2"):
            kind = parts[0].split("-", 1)[1]
            # Streaming mode holds the connection until END
            conn.settimeout(None)
            stream_logs(conn, kind, parts[1])
            return
        ok, msg = handle_line(line)
        if isinstance(msg, (dict, list)):
            _reply_json(conn, ok, msg)
        else:
            _reply(conn, ok, str(msg))
    except OSError:
        pass
    finally:
        try:
            conn.close()
        except OSError:
            pass


def serve() -> int:
    if os.geteuid() != 0:
        print("ctl_server must run as root", file=sys.stderr)
        return 1

    sock_dir = Path(SOCKET_PATH).parent
    sock_dir.mkdir(parents=True, exist_ok=True)
    if Path(SOCKET_PATH).exists():
        Path(SOCKET_PATH).unlink()

    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(SOCKET_PATH)
    os.chown(SOCKET_PATH, 0, 0)
    try:
        import grp

        gid = grp.getgrnam("port-dashboard").gr_gid
        # API user must traverse the runtime dir and talk on the socket.
        os.chown(sock_dir, 0, gid)
        os.chmod(sock_dir, 0o750)
        os.chown(SOCKET_PATH, 0, gid)
        os.chmod(SOCKET_PATH, 0o660)
    except KeyError:
        os.chmod(SOCKET_PATH, 0o600)

    server.listen(32)
    server.settimeout(1.0)
    print(f"listening on {SOCKET_PATH}", flush=True)

    running = True

    def _stop(_signum: int, _frame: object) -> None:
        nonlocal running
        running = False

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)

    while running:
        try:
            conn, _ = server.accept()
        except socket.timeout:
            continue
        except OSError:
            break
        # Concurrent clients: log streams must not block docker/pm2/kill.
        thread = threading.Thread(
            target=_handle_client,
            args=(conn,),
            name="ctl-client",
            daemon=True,
        )
        thread.start()

    server.close()
    try:
        Path(SOCKET_PATH).unlink(missing_ok=True)
    except OSError:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(serve())
