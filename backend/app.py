"""
System Port & Process Monitor — FastAPI backend.

Binds to 127.0.0.1 only (via uvicorn/systemd).
Inspection APIs plus guarded stop/restart/kill via a root helper.
Never executes user-supplied shell strings. Does not expose env, cmdline, or secrets.
"""

from __future__ import annotations

import json
import logging
import os
import re
import socket
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

APP_NAME = "System Port & Process Monitor"
SS_TIMEOUT_SEC = 8
SYSTEMCTL_TIMEOUT_SEC = 5
CTL_TIMEOUT_SEC = 12
UNAVAILABLE = "unavailable"
CTL_SOCKET = "/run/port-dashboard/ctl.sock"

UNIT_RE = re.compile(r"^[A-Za-z0-9@_.\\-]+\.service$")

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

# Match users:(("name",pid=123,fd=4),("other",pid=456,fd=7))
_PROCESS_RE = re.compile(
    r'\("([^"]*)",pid=(\d+),fd=\d+\)'
)

logger = logging.getLogger("port-dashboard")

app = FastAPI(
    title=APP_NAME,
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _run_cmd(args: list[str], timeout: float) -> subprocess.CompletedProcess[str]:
    """Safe subprocess helper — never uses shell=True."""
    return subprocess.run(
        args,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
        shell=False,
        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"},
    )


def _split_host_port(local_addr: str) -> tuple[str, int | None]:
    """
    Parse ss Local Address:Port into (address, port).
    Handles IPv6 ([::1]:80), IPv4 (0.0.0.0:80), wildcards (*:80), and %iface.
    """
    local_addr = local_addr.strip()
    if not local_addr:
        return UNAVAILABLE, None

    if local_addr.startswith("["):
        # [addr%iface]:port
        end = local_addr.find("]")
        if end == -1:
            return local_addr, None
        host = local_addr[1:end]
        rest = local_addr[end + 1 :]
        if rest.startswith(":"):
            try:
                return host, int(rest[1:])
            except ValueError:
                return host, None
        return host, None

    # IPv4 or * — last colon separates port
    if ":" not in local_addr:
        return local_addr, None
    host, _, port_s = local_addr.rpartition(":")
    try:
        return host or "*", int(port_s)
    except ValueError:
        return local_addr, None


def _parse_process_field(field: str) -> list[tuple[str, int]]:
    """Extract (comm, pid) pairs from ss users:(...) field."""
    if not field or field == "-":
        return []
    return [(name, int(pid)) for name, pid in _PROCESS_RE.findall(field)]


def _exe_for_pid(pid: int) -> str:
    try:
        target = os.readlink(f"/proc/{pid}/exe")
        # Kernel appends " (deleted)" for replaced binaries
        if target.endswith(" (deleted)"):
            target = target[: -len(" (deleted)")]
        return target or UNAVAILABLE
    except OSError:
        return UNAVAILABLE


def _unit_from_cgroup(pid: int) -> str | None:
    try:
        text = Path(f"/proc/{pid}/cgroup").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None

    # Prefer the last matching .service in any hierarchy
    found: str | None = None
    for line in text.splitlines():
        # cgroup v2: 0::/system.slice/nginx.service
        # cgroup v1: 1:name=systemd:/system.slice/nginx.service
        path = line.split(":", 2)[-1] if ":" in line else line
        for match in re.finditer(r"([^/\s]+\.service)", path):
            name = match.group(1)
            # Skip transient scope wrappers when a real service is present later
            if name.endswith(".scope"):
                continue
            if name in ("init.scope", "user.slice"):
                continue
            found = name
    return found


def _valid_unit(unit: str) -> bool:
    return bool(unit) and UNIT_RE.fullmatch(unit) is not None


def _is_user_session_unit(unit: str | None) -> bool:
    return bool(unit) and unit.startswith("user@") and unit.endswith(".service")


def _unit_protected(unit: str) -> bool:
    """Units that must not be stopped/started/restarted as a whole."""
    if unit in PROTECTED_UNITS:
        return True
    if unit.startswith("systemd-"):
        return True
    # Never stop/restart the whole user session (user@1000.service)
    if _is_user_session_unit(unit):
        return True
    return False


def _pid_kill_forbidden_by_unit(unit: str | None) -> bool:
    """
    Hard units where even PID kill is refused (nginx/ssh/etc).
    User-session units are NOT in this list so stuck apps (daphne) can be killed.
    """
    if not unit:
        return False
    if unit in PROTECTED_UNITS or unit.startswith("systemd-"):
        return True
    return False


def _comm_for_pid(pid: int) -> str | None:
    try:
        return Path(f"/proc/{pid}/comm").read_text(encoding="utf-8").strip() or None
    except OSError:
        return None


def _max_pid() -> int:
    try:
        return int(Path("/proc/sys/kernel/pid_max").read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        return 2**22


def _ctl_exchange(command: str) -> str:
    """Send one line to the control daemon; return OK payload (without 'OK ' prefix)."""
    request = (command.strip() + "\n").encode("utf-8")
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(CTL_TIMEOUT_SEC)
            sock.connect(CTL_SOCKET)
            sock.sendall(request)
            chunks: list[bytes] = []
            while True:
                piece = sock.recv(65536)
                if not piece:
                    break
                chunks.append(piece)
                if b"\n" in piece:
                    break
            raw = b"".join(chunks).decode("utf-8", errors="replace").strip()
    except FileNotFoundError:
        logger.error("control socket missing path=%s", CTL_SOCKET)
        raise HTTPException(
            status_code=503,
            detail="Process control daemon is not running.",
        )
    except (TimeoutError, socket.timeout):
        logger.error("control socket timed out command=%s", command[:80])
        raise HTTPException(status_code=504, detail="Process control timed out.")
    except OSError as exc:
        logger.warning("control socket error: %s", exc)
        raise HTTPException(
            status_code=503,
            detail="Process control daemon is unavailable.",
        )

    if not raw:
        raise HTTPException(status_code=502, detail="Process control failed.")

    if raw.startswith("OK"):
        return raw[2:].lstrip()

    err = raw[4:].strip() if raw.startswith("ERR ") else raw
    logger.warning("control helper failed command=%s err=%s", command[:80], err[:200])
    lower = err.lower()
    if "protected" in lower:
        raise HTTPException(status_code=403, detail="Target is protected.")
    if "not found" in lower:
        raise HTTPException(status_code=404, detail="Target not found.")
    if "docker" in lower and ("cannot connect" in lower or "not found" in lower):
        raise HTTPException(status_code=503, detail="Docker is unavailable.")
    if "pm2" in lower and "not found" in lower:
        raise HTTPException(status_code=503, detail="PM2 is unavailable.")
    raise HTTPException(status_code=502, detail="Process control failed.")


def _run_ctl(
    action: Literal["stop", "start", "restart", "kill", "killforce"], target: str
) -> None:
    """Invoke the root control daemon over a local Unix socket (no sudo)."""
    if not re.fullmatch(r"[A-Za-z0-9@_.\\-]+", target) and not (
        action in ("kill", "killforce") and target.isdigit()
    ):
        raise HTTPException(status_code=400, detail="Invalid target.")
    _ctl_exchange(f"{action} {target}")


def _ctl_json(command: str) -> Any:
    payload = _ctl_exchange(command)
    if not payload:
        return {}
    try:
        return json.loads(payload)
    except json.JSONDecodeError:
        logger.warning("control helper returned non-json for %s", command)
        raise HTTPException(status_code=502, detail="Process control failed.")


class ServiceActionRequest(BaseModel):
    unit: str = Field(min_length=1, max_length=256)
    confirm: str = Field(min_length=1, max_length=256)


class KillProcessRequest(BaseModel):
    pid: int = Field(ge=2)
    confirm: str = Field(min_length=1, max_length=64)
    force: bool = False


def _systemctl_active_state(unit: str) -> str:
    if not _valid_unit(unit):
        return UNAVAILABLE
    try:
        result = _run_cmd(
            ["systemctl", "show", unit, "--property=ActiveState", "--value"],
            timeout=SYSTEMCTL_TIMEOUT_SEC,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return UNAVAILABLE
    state = (result.stdout or "").strip()
    if result.returncode != 0 or not state:
        return UNAVAILABLE
    return state


def _enrich_pid(pid: int, comm: str) -> dict[str, Any]:
    unit = _unit_from_cgroup(pid)
    return {
        "process_name": comm or UNAVAILABLE,
        "pid": pid,
        "executable": _exe_for_pid(pid),
        "service": unit or UNAVAILABLE,
        "service_status": _systemctl_active_state(unit) if unit else UNAVAILABLE,
    }


def _placeholder_process() -> dict[str, Any]:
    return {
        "process_name": UNAVAILABLE,
        "pid": None,
        "executable": UNAVAILABLE,
        "service": UNAVAILABLE,
        "service_status": UNAVAILABLE,
    }


def _collect_listening_sockets() -> tuple[list[dict[str, Any]], list[str]]:
    """
    Run `ss -H -ltunp` and return (entries, warnings).
    One row per (socket, process) association; sockets with no process get one row.
    """
    warnings: list[str] = []
    try:
        result = _run_cmd(
            ["ss", "-H", "-ltunp"],
            timeout=SS_TIMEOUT_SEC,
        )
    except FileNotFoundError:
        raise HTTPException(
            status_code=503,
            detail="Socket inspection tool is unavailable on this host.",
        )
    except subprocess.TimeoutExpired:
        raise HTTPException(
            status_code=504,
            detail="Socket inspection timed out.",
        )
    except OSError:
        raise HTTPException(
            status_code=503,
            detail="Unable to inspect listening sockets.",
        )

    if result.returncode != 0:
        warnings.append("Socket inspection returned a non-zero exit status.")

    entries: list[dict[str, Any]] = []
    for raw_line in (result.stdout or "").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        parts = line.split()
        # Expected: Netid State Recv-Q Send-Q LocalAddress:Port PeerAddress:Port [Process]
        if len(parts) < 6:
            continue

        netid = parts[0].lower()
        if netid.startswith("tcp"):
            protocol = "tcp"
        elif netid.startswith("udp"):
            protocol = "udp"
        else:
            continue

        state = parts[1]
        local_raw = parts[4]
        process_field = parts[6] if len(parts) > 6 else ""

        address, port = _split_host_port(local_raw)
        if port is None:
            continue

        procs = _parse_process_field(process_field)
        if not procs:
            row = {
                "port": port,
                "protocol": protocol,
                "address": address,
                "state": state,
                **_placeholder_process(),
            }
            entries.append(row)
            continue

        for comm, pid in procs:
            enriched = _enrich_pid(pid, comm)
            entries.append(
                {
                    "port": port,
                    "protocol": protocol,
                    "address": address,
                    "state": state,
                    **enriched,
                }
            )

    # Stable sort: protocol, port, address, pid
    entries.sort(
        key=lambda e: (
            e["protocol"],
            e["port"],
            str(e["address"]),
            e["pid"] if e["pid"] is not None else -1,
        )
    )
    return entries, warnings


def _summarize(entries: list[dict[str, Any]]) -> dict[str, int]:
    unique_ports = {(e["protocol"], e["port"]) for e in entries}
    # Count distinct listening socket endpoints (protocol, address, port)
    sockets = {(e["protocol"], e["address"], e["port"]) for e in entries}
    pids = {e["pid"] for e in entries if e["pid"] is not None}
    tcp = sum(1 for s in sockets if s[0] == "tcp")
    udp = sum(1 for s in sockets if s[0] == "udp")
    return {
        "total_listening_sockets": len(sockets),
        "unique_ports": len({p for _, p in unique_ports}),
        "identified_processes": len(pids),
        "tcp_listening_sockets": tcp,
        "udp_listening_sockets": udp,
    }


def _read_uptime_seconds() -> float | None:
    try:
        raw = Path("/proc/uptime").read_text(encoding="utf-8").split()[0]
        return float(raw)
    except (OSError, IndexError, ValueError):
        return None


def _read_loadavg() -> list[float] | None:
    try:
        parts = Path("/proc/loadavg").read_text(encoding="utf-8").split()[:3]
        return [float(x) for x in parts]
    except (OSError, ValueError):
        return None


def _read_meminfo() -> dict[str, int | None]:
    out: dict[str, int | None] = {
        "mem_total_kb": None,
        "mem_available_kb": None,
        "mem_free_kb": None,
    }
    try:
        text = Path("/proc/meminfo").read_text(encoding="utf-8")
    except OSError:
        return out
    mapping = {
        "MemTotal:": "mem_total_kb",
        "MemAvailable:": "mem_available_kb",
        "MemFree:": "mem_free_kb",
    }
    for line in text.splitlines():
        for prefix, key in mapping.items():
            if line.startswith(prefix):
                bits = line.split()
                if len(bits) >= 2:
                    try:
                        out[key] = int(bits[1])
                    except ValueError:
                        pass
    return out


@app.get("/api/health")
def health() -> dict[str, Any]:
    return {
        "status": "ok",
        "service": APP_NAME,
        "timestamp": _utc_now_iso(),
    }


@app.get("/api/ports")
def ports() -> dict[str, Any]:
    started = time.monotonic()
    entries, warnings = _collect_listening_sockets()
    summary = _summarize(entries)
    return {
        "timestamp": _utc_now_iso(),
        "elapsed_ms": int((time.monotonic() - started) * 1000),
        "summary": summary,
        "ports": entries,
        "warnings": warnings,
    }


@app.get("/api/system")
def system_info() -> dict[str, Any]:
    uptime = _read_uptime_seconds()
    mem = _read_meminfo()
    return {
        "timestamp": _utc_now_iso(),
        "hostname": socket.gethostname(),
        "uptime_seconds": uptime,
        "loadavg": _read_loadavg(),
        **mem,
    }


def _service_action(
    action: Literal["stop", "start", "restart"], body: ServiceActionRequest
) -> dict[str, Any]:
    unit = body.unit.strip()
    if not _valid_unit(unit):
        raise HTTPException(status_code=400, detail="Invalid unit name.")
    if body.confirm != unit:
        raise HTTPException(status_code=400, detail="Confirmation does not match unit name.")
    if _unit_protected(unit):
        raise HTTPException(status_code=403, detail="Target is protected.")
    _run_ctl(action, unit)
    return {
        "status": "ok",
        "action": action,
        "unit": unit,
        "timestamp": _utc_now_iso(),
    }


class ServicesLookupRequest(BaseModel):
    units: list[str] = Field(default_factory=list, max_length=200)


def _discover_loaded_services() -> list[dict[str, Any]]:
    """
    List loaded systemd services in active/inactive/failed states.
    Includes stopped-but-still-loaded units (e.g. postgresql@16-main.service).
    """
    try:
        result = _run_cmd(
            [
                "systemctl",
                "list-units",
                "--type=service",
                "--state=active,inactive,failed",
                "--all",
                "--no-legend",
                "--plain",
                "--no-pager",
            ],
            timeout=SYSTEMCTL_TIMEOUT_SEC,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return []

    items: list[dict[str, Any]] = []
    seen: set[str] = set()
    for line in (result.stdout or "").splitlines():
        parts = line.split(None, 4)
        if len(parts) < 3:
            continue
        unit = parts[0].strip()
        # list-units may prefix with ● 
        unit = unit.lstrip("●").strip()
        if not _valid_unit(unit) or unit in seen or _unit_protected(unit):
            continue
        seen.add(unit)
        active_state = parts[2].strip() if len(parts) > 2 else UNAVAILABLE
        items.append(
            {
                "unit": unit,
                "status": active_state or UNAVAILABLE,
                "protected": False,
                "source": "systemd",
            }
        )
        if len(items) >= 300:
            break
    items.sort(key=lambda x: x["unit"])
    return items


@app.get("/api/services")
def services_status(units: str = "") -> dict[str, Any]:
    """
    Return ActiveState for requested units (comma-separated).
    Used so stopped services remain visible after they leave the ports table.
    """
    requested = [u.strip() for u in units.split(",") if u.strip()]
    return _services_payload(requested)


@app.post("/api/services/status")
def services_status_post(body: ServicesLookupRequest) -> dict[str, Any]:
    return _services_payload(body.units)


@app.get("/api/services/catalog")
def services_catalog() -> dict[str, Any]:
    """Loaded systemd services (active/inactive/failed), excluding protected units."""
    return {
        "timestamp": _utc_now_iso(),
        "services": _discover_loaded_services(),
    }


def _services_payload(requested: list[str]) -> dict[str, Any]:
    seen: set[str] = set()
    items: list[dict[str, Any]] = []
    for raw in requested[:200]:
        unit = raw.strip()
        if not _valid_unit(unit) or unit in seen:
            continue
        seen.add(unit)
        items.append(
            {
                "unit": unit,
                "status": _systemctl_active_state(unit),
                "protected": _unit_protected(unit),
            }
        )
    items.sort(key=lambda x: x["unit"])
    return {"timestamp": _utc_now_iso(), "services": items}


@app.post("/api/service/stop")
def service_stop(body: ServiceActionRequest) -> dict[str, Any]:
    return _service_action("stop", body)


@app.post("/api/service/start")
def service_start(body: ServiceActionRequest) -> dict[str, Any]:
    return _service_action("start", body)


@app.post("/api/service/restart")
def service_restart(body: ServiceActionRequest) -> dict[str, Any]:
    return _service_action("restart", body)


DOCKER_REF_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
PM2_REF_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")


class RuntimeActionRequest(BaseModel):
    target: str = Field(min_length=1, max_length=128)
    confirm: str = Field(min_length=1, max_length=128)


@app.get("/api/docker")
def docker_list() -> dict[str, Any]:
    # Soft-fail so the dashboard refresh never hangs on Docker alone.
    try:
        data = _ctl_json("docker-list")
        if not isinstance(data, dict):
            data = {}
        err = data.get("error")
        return {
            "timestamp": _utc_now_iso(),
            "containers": data.get("containers") or [],
            "error": err,
            "available": err is None,
        }
    except HTTPException as exc:
        return {
            "timestamp": _utc_now_iso(),
            "containers": [],
            "error": str(exc.detail),
            "available": False,
        }


@app.post("/api/docker/{action}")
def docker_action(action: str, body: RuntimeActionRequest) -> dict[str, Any]:
    if action not in ("start", "stop", "restart"):
        raise HTTPException(status_code=400, detail="Invalid docker action.")
    target = body.target.strip()
    if body.confirm != target:
        raise HTTPException(status_code=400, detail="Confirmation does not match target.")
    if not DOCKER_REF_RE.fullmatch(target):
        raise HTTPException(status_code=400, detail="Invalid container reference.")
    _ctl_exchange(f"docker-{action} {target}")
    return {
        "status": "ok",
        "runtime": "docker",
        "action": action,
        "target": target,
        "timestamp": _utc_now_iso(),
    }


@app.get("/api/pm2")
def pm2_list() -> dict[str, Any]:
    # Soft-fail so the dashboard refresh never hangs on PM2 alone.
    try:
        data = _ctl_json("pm2-list")
        if not isinstance(data, dict):
            data = {}
        err = data.get("error")
        return {
            "timestamp": _utc_now_iso(),
            "processes": data.get("processes") or [],
            "user": data.get("user"),
            "error": err,
            "available": err is None,
        }
    except HTTPException as exc:
        return {
            "timestamp": _utc_now_iso(),
            "processes": [],
            "user": None,
            "error": str(exc.detail),
            "available": False,
        }


@app.post("/api/pm2/{action}")
def pm2_action(action: str, body: RuntimeActionRequest) -> dict[str, Any]:
    if action not in ("start", "stop", "restart", "delete"):
        raise HTTPException(status_code=400, detail="Invalid pm2 action.")
    target = body.target.strip()
    if body.confirm != target:
        raise HTTPException(status_code=400, detail="Confirmation does not match target.")
    if not PM2_REF_RE.fullmatch(target):
        raise HTTPException(status_code=400, detail="Invalid pm2 reference.")
    _ctl_exchange(f"pm2-{action} {target}")
    return {
        "status": "ok",
        "runtime": "pm2",
        "action": action,
        "target": target,
        "timestamp": _utc_now_iso(),
    }


@app.websocket("/api/logs/ws")
async def logs_websocket(websocket: WebSocket) -> None:
    """
    Live log stream bridged from the root control helper.
    Query: runtime=systemd|docker|pm2 & target=<unit-or-name>
    """
    runtime = (websocket.query_params.get("runtime") or "").strip().lower()
    target = (websocket.query_params.get("target") or "").strip()
    if runtime not in ("systemd", "docker", "pm2"):
        await websocket.close(code=1008)
        return
    if runtime == "systemd" and not UNIT_RE.fullmatch(target):
        await websocket.close(code=1008)
        return
    if runtime == "docker" and not DOCKER_REF_RE.fullmatch(target):
        await websocket.close(code=1008)
        return
    if runtime == "pm2" and not PM2_REF_RE.fullmatch(target):
        await websocket.close(code=1008)
        return

    await websocket.accept()
    await websocket.send_text(f"[connecting to {runtime} logs: {target}]")

    import asyncio

    loop = asyncio.get_event_loop()

    def _stream() -> None:
        cmd = f"logs-{runtime} {target}\n".encode("utf-8")
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
                sock.settimeout(10.0)
                sock.connect(CTL_SOCKET)
                sock.sendall(cmd)
                sock.settimeout(None)
                buf = b""
                started = False
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    buf += chunk
                    while b"\n" in buf:
                        line, buf = buf.split(b"\n", 1)
                        text = line.decode("utf-8", errors="replace")
                        if not started:
                            if text.startswith("ERR"):
                                asyncio.run_coroutine_threadsafe(
                                    websocket.send_text(f"[error] {text[4:].strip()}"),
                                    loop,
                                ).result(timeout=5)
                                return
                            if text.startswith("OK"):
                                started = True
                                asyncio.run_coroutine_threadsafe(
                                    websocket.send_text("[stream started]"),
                                    loop,
                                ).result(timeout=5)
                                continue
                        if text == "END":
                            asyncio.run_coroutine_threadsafe(
                                websocket.send_text("[stream ended]"),
                                loop,
                            ).result(timeout=5)
                            return
                        if text.startswith("L "):
                            asyncio.run_coroutine_threadsafe(
                                websocket.send_text(text[2:]),
                                loop,
                            ).result(timeout=5)
        except Exception as exc:  # noqa: BLE001 — surface to client
            try:
                asyncio.run_coroutine_threadsafe(
                    websocket.send_text(f"[error] {exc}"),
                    loop,
                ).result(timeout=5)
            except Exception:
                pass

    try:
        await loop.run_in_executor(None, _stream)
    except WebSocketDisconnect:
        return
    except Exception:
        try:
            await websocket.send_text("[error] log stream failed")
        except Exception:
            pass
    finally:
        try:
            await websocket.close()
        except Exception:
            pass


@app.post("/api/process/kill")
def process_kill(body: KillProcessRequest) -> dict[str, Any]:
    pid = body.pid
    if body.confirm != str(pid):
        raise HTTPException(status_code=400, detail="Confirmation does not match PID.")
    if pid > _max_pid():
        raise HTTPException(status_code=400, detail="Invalid PID.")
    if pid in (1, os.getpid(), os.getppid()):
        raise HTTPException(status_code=403, detail="Target is protected.")

    comm = _comm_for_pid(pid)
    if comm is None:
        raise HTTPException(status_code=404, detail="Target not found.")
    if comm in PROTECTED_COMM:
        raise HTTPException(status_code=403, detail="Target is protected.")

    unit = _unit_from_cgroup(pid)
    if _pid_kill_forbidden_by_unit(unit):
        raise HTTPException(status_code=403, detail="Target is protected.")

    # Prefer Stop/Restart for normal systemd services (not user session scopes)
    if (
        unit
        and _valid_unit(unit)
        and not _unit_protected(unit)
        and not _is_user_session_unit(unit)
    ):
        raise HTTPException(
            status_code=409,
            detail="Process belongs to a systemd unit; use Stop or Restart instead.",
        )

    action: Literal["kill", "killforce"] = "killforce" if body.force else "kill"
    _run_ctl(action, str(pid))
    return {
        "status": "ok",
        "action": action,
        "pid": pid,
        "timestamp": _utc_now_iso(),
    }


@app.exception_handler(Exception)
async def unhandled_exception_handler(_request: Any, _exc: Exception) -> JSONResponse:
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error."},
    )
