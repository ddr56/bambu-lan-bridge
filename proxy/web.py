"""Admin page and its JSON API: status, printers, certificates, logs.

Protected by HTTP basic auth (any user name, password from ADMIN_PASSWORD or
data/admin_password), unless bound to loopback only. Printer changes are written
to config.yaml and take effect on "Apply and restart", which exits the process
for the container to restart. An uploaded certificate is checked and takes
effect at once.
"""

from __future__ import annotations

import asyncio
import base64
import hmac
import ipaddress
import json
import logging
import os
import platform
import re
import secrets
import shutil
import tempfile
import time
from importlib import metadata
from pathlib import Path

import yaml
from aiohttp import web

from . import __version__
from .signer import Signer

log = logging.getLogger("web")

STATIC = Path(__file__).parent / "static"
MODELS = {"O1D": "H2D", "O1C": "H2C", "O1C2": "H2C", "O1S": "H2S", "O2D": "H2D Pro", "N7": "P2S",
          "C11": "P1P", "C12": "P1S", "N2S": "A1", "N1": "A1 mini", "BL-P001": "X1C", "BL-P002": "X1",
          "C13": "X1E"}
CERT_FILES = ("key.pem", "chain.pem", "crl.pem")
SERIAL_RE = re.compile(r"^[A-Z0-9]{8,20}$")
# Proxy-wide options the Settings tab edits, with the defaults main.py applies.
SETTINGS = {
    "mode": "full",                 # full | read_only
    "present_developer_mode": True,
    "ssdp": True,
}
CHOICES = {"mode": ("full", "read_only")}
# Loggers raised to DEBUG by the debug toggle; auto-reverts after this many minutes.
DEBUG_LOGGERS = ("proxy", "router", "mqtt", "upstream", "signer", "web", "discovery", "relay", "ssdp", "tls")
DEBUG_MINUTES = 20


def _version(pkg: str) -> str:
    try:
        return metadata.version(pkg)
    except metadata.PackageNotFoundError:
        return "?"


class Admin:
    def __init__(self, cfg_path: Path, cfg: dict, data: Path, certs: Path, routers: dict, printers: list[dict],
                 discovery, logbuf, stop: asyncio.Event) -> None:
        self.cfg_path, self.cfg, self.data, self.certs = cfg_path, cfg, data, certs
        self.routers, self.printers = routers, printers
        self.discovery, self.logbuf, self.stop = discovery, logbuf, stop
        self.started = time.time()
        self.restart_needed = False
        # What this process started with; the Settings tab edits self.cfg for the next start.
        self.running = {k: cfg.get(k, d) for k, d in SETTINGS.items()}
        self.debug_until = 0.0
        self._debug_timer = None
        # Bound to loopback only (admin_bind: 127.0.0.1): nobody else can reach it, so no password.
        self.loopback_only = cfg.get("admin_bind", "0.0.0.0") in ("127.0.0.1", "::1", "localhost")
        self.password = "" if self.loopback_only else self._password()

    # ---------------------------------------------------------------- auth

    def _password(self) -> str:
        if os.environ.get("ADMIN_PASSWORD"):
            return os.environ["ADMIN_PASSWORD"]
        path = self.data / "admin_password"
        if not path.exists():
            path.write_text(secrets.token_urlsafe(12) + "\n")
            path.chmod(0o600)
            log.warning("admin password generated: see %s", path)
        return path.read_text().strip()

    @web.middleware
    async def auth(self, request: web.Request, handler):
        if self.loopback_only:
            return await handler(request)
        header = request.headers.get("Authorization", "")
        if header.startswith("Basic "):
            try:
                _, _, given = base64.b64decode(header[6:]).decode().partition(":")
            except (ValueError, UnicodeDecodeError):
                given = ""
            if hmac.compare_digest(given.encode(), self.password.encode()):
                return await handler(request)
        return web.Response(status=401, headers={"WWW-Authenticate": 'Basic realm="bambu-lan-bridge"'})

    # ---------------------------------------------------------------- status

    def cert_info(self) -> dict:
        if not all((self.certs / f).exists() for f in CERT_FILES[:2]):
            return {"present": False}
        try:
            s = Signer(self.certs)
        except Exception as e:  # noqa: BLE001
            return {"present": True, "error": str(e)}
        return {"present": True, "cert_id": s.cert_id, "not_after": s.not_after.isoformat(),
                "days_left": int((s.not_after.timestamp() - time.time()) // 86400)}

    async def status(self, request: web.Request) -> web.Response:
        detected = self.discovery.printers() if self.discovery else []
        firmware = {d["serial"]: d["firmware"] for d in detected}
        configured = {p["serial"] for p in self.cfg.get("printers", [])}
        printers = []
        for p in self.printers:
            r = self.routers.get(p["serial"])
            printers.append({
                "serial": p["serial"], "virtual_serial": p.get("virtual_serial"), "name": p.get("name"),
                "model": MODELS.get(p.get("model_code", ""), p.get("model_code", "")),
                "virtual_ip": p["virtual_ip"], "lan_ip": p.get("lan_ip"),
                "firmware": firmware.get(p["serial"]), **(r.status() if r else {}),
            })
        return web.json_response({
            "version": __version__,
            "versions": {"python": platform.python_version(), "paho-mqtt": _version("paho-mqtt"),
                         "aiohttp": _version("aiohttp"), "cryptography": _version("cryptography")},
            "uptime_s": round(time.time() - self.started),
            "restart_needed": self.restart_needed,
            "debug": {"on": self.debug_until > time.time(), "until": self.debug_until},
            "cert": self.cert_info(),
            "printers": printers,
            "detected": [dict(d, model=MODELS.get(d["model_code"], d["model_code"]),
                              configured=d["serial"] in configured) for d in detected],
        })

    async def logs(self, request: web.Request) -> web.Response:
        return web.json_response(self.logbuf.since(int(request.query.get("after", 0))))

    # ---------------------------------------------------------------- debug

    def _set_debug(self, on: bool) -> None:
        """Raise or lower the proxy's log verbosity at runtime. Debug logs the raw
        MQTT frames both ways and client TLS failures."""
        level = logging.DEBUG if on else logging.INFO
        logging.getLogger().setLevel(level)
        self.logbuf.setLevel(level)
        for name in DEBUG_LOGGERS:
            logging.getLogger(name).setLevel(level)
        logging.getLogger("asyncio").setLevel(logging.DEBUG if on else logging.WARNING)
        log.info("debug logging %s", "ON (extra frame/TLS detail captured)" if on else "off")

    async def debug_toggle(self, request: web.Request) -> web.Response:
        on = bool((await request.json()).get("on"))
        if self._debug_timer:
            self._debug_timer.cancel()
            self._debug_timer = None
        self._set_debug(on)
        if on:
            # Auto-revert so verbose logs don't pile up or leak if left on.
            self.debug_until = time.time() + DEBUG_MINUTES * 60
            self._debug_timer = asyncio.get_running_loop().call_later(
                DEBUG_MINUTES * 60, lambda: self._set_debug(False))
        else:
            self.debug_until = 0.0
        return web.json_response({"on": on, "until": self.debug_until})

    async def diagnostics(self, request: web.Request) -> web.Response:
        """A sharable snapshot for problem-solving: versions, each printer's state and
        latest full report (the model/firmware-specific fields), recent commands and
        the log tail. Access codes are not included."""
        detected = self.discovery.printers() if self.discovery else []
        cfg_safe = {k: v for k, v in self.cfg.items() if k != "printers"}
        cfg_safe["printers"] = [{k: v for k, v in p.items() if k != "access_code"}
                                | {"access_code": "set" if p.get("access_code") else "unset"}
                                for p in self.cfg.get("printers", [])]
        printers = []
        for p in self.printers:
            r = self.routers.get(p["serial"])
            st = r.status() if r else {}
            printers.append({
                "serial": p["serial"], "name": p.get("name"), "model_code": p.get("model_code"),
                "model": MODELS.get(p.get("model_code", ""), p.get("model_code", "")),
                "firmware": next((d["firmware"] for d in detected if d["serial"] == p["serial"]), None),
                **st,
                "last_report": r.last_report.decode("utf-8", "replace") if r and r.last_report else "",
            })
        bundle = {
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "version": __version__,
            "versions": {"python": platform.python_version(), "paho-mqtt": _version("paho-mqtt"),
                         "aiohttp": _version("aiohttp"), "cryptography": _version("cryptography")},
            "uptime_s": round(time.time() - self.started),
            "cert": self.cert_info(),
            "config": cfg_safe,
            "printers": printers,
            "detected": detected,
            "log": self.logbuf.since(0),
        }
        name = f"bambu-lan-bridge-diagnostics-{time.strftime('%Y%m%d-%H%M%S')}.json"
        return web.json_response(bundle, headers={"Content-Disposition": f'attachment; filename="{name}"'},
                                 dumps=lambda o: json.dumps(o, indent=2))

    # ---------------------------------------------------------------- printers

    def _save_cfg(self) -> None:
        tmp = self.cfg_path.with_suffix(".tmp")
        tmp.write_text(yaml.safe_dump(self.cfg, sort_keys=False))
        tmp.replace(self.cfg_path)
        self.restart_needed = True

    async def list_printers(self, request: web.Request) -> web.Response:
        return web.json_response([{k: v for k, v in p.items() if k != "access_code"}
                                  | {"has_code": bool(p.get("access_code"))} for p in self.cfg.get("printers", [])])

    async def save_printer(self, request: web.Request) -> web.Response:
        body = await request.json()
        serial = str(body.get("serial", "")).strip().upper()
        if not SERIAL_RE.match(serial):
            raise web.HTTPBadRequest(text="The serial should be 8-20 letters and digits, as on the printer's label.")
        printers = self.cfg.setdefault("printers", [])
        existing = next((p for p in printers if p["serial"] == serial), None)
        entry = dict(existing or {"serial": serial})
        for key in ("name", "model_code", "virtual_ip", "lan_ip", "virtual_serial"):
            if key in body:
                value = str(body[key] or "").strip()
                if value:
                    entry[key] = value
                else:
                    entry.pop(key, None)
        code = str(body.get("access_code") or "").strip()
        if code:
            entry["access_code"] = code
        problems = self._check(entry, [p for p in printers if p["serial"] != serial])
        if problems:
            raise web.HTTPBadRequest(text=" ".join(problems))
        if existing:
            printers[printers.index(existing)] = entry
        else:
            printers.append(entry)
        self._save_cfg()
        log.info("printer %s saved (%s)", serial, "updated" if existing else "added")
        warning = None
        if not entry.get("lan_ip"):
            warning = "This printer has no IP yet, so it can't be reached. Add its LAN IP so the proxy can connect."
        return web.json_response({"ok": True, "warning": warning})

    @staticmethod
    def _check(entry: dict, others: list[dict]) -> list[str]:
        problems = []
        for key, label in (("virtual_ip", "Virtual IP"), ("lan_ip", "Printer IP")):
            if entry.get(key):
                try:
                    ipaddress.ip_address(entry[key])
                except ValueError:
                    problems.append(f"{label} {entry[key]!r} is not an IPv4 address.")
        if not entry.get("virtual_ip"):
            problems.append("A virtual IP is required: a free address on your LAN for this printer.")
        if not entry.get("access_code"):
            problems.append("An access code is required (printer screen: Settings, then the LAN/network section).")
        if not entry.get("name"):
            entry["name"] = entry["serial"]
        if not entry.get("model_code"):
            problems.append("A model is required.")
        if entry.get("virtual_ip") and entry.get("virtual_ip") == entry.get("lan_ip"):
            problems.append("The virtual IP must differ from the printer's own IP.")
        for o in others:
            if entry.get("virtual_ip") and entry["virtual_ip"] in (o.get("virtual_ip"), o.get("lan_ip")):
                problems.append(f"{entry['virtual_ip']} is already used by {o.get('name', o['serial'])}.")
        return problems

    async def delete_printer(self, request: web.Request) -> web.Response:
        serial = request.match_info["serial"]
        printers = self.cfg.get("printers", [])
        kept = [p for p in printers if p["serial"] != serial]
        if len(kept) == len(printers):
            raise web.HTTPNotFound(text=f"No printer {serial} in the configuration.")
        self.cfg["printers"] = kept
        self._save_cfg()
        log.info("printer %s removed", serial)
        return web.json_response({"ok": True})

    async def restart(self, request: web.Request) -> web.Response:
        log.info("restart requested from the admin page")
        asyncio.get_running_loop().call_later(0.5, self.stop.set)
        return web.json_response({"ok": True})

    # ---------------------------------------------------------------- certificates

    async def upload_certs(self, request: web.Request) -> web.Response:
        files: dict[str, bytes] = {}
        async for part in await request.multipart():
            if part.name in CERT_FILES:
                files[part.name] = await part.read(decode=False)
        missing = [f for f in CERT_FILES if f not in files and f != "crl.pem"]
        if missing:
            raise web.HTTPBadRequest(text=f"Choose key.pem and chain.pem (crl.pem is optional); missing: {', '.join(missing)}.")
        with tempfile.TemporaryDirectory() as tmp:
            for name, content in files.items():
                (Path(tmp) / name).write_bytes(content)
            try:
                signer = Signer(Path(tmp))
                signer.envelope({"command": "check", "sequence_id": "20000"})
            except Exception as e:  # noqa: BLE001
                raise web.HTTPBadRequest(text=f"These files don't form a usable key set: {e}")
            self.certs.mkdir(parents=True, exist_ok=True)
            for name in files:
                shutil.copyfile(Path(tmp) / name, self.certs / name)
            (self.certs / "key.pem").chmod(0o600)
        mode = self.cfg.get("mode", "full")
        for r in self.routers.values():
            r.signer, r.mode = signer, mode
            r.cert_ok = {"lan": False}
        log.info("signing certificate replaced (cert valid until %s)", signer.not_after.date())
        return web.json_response(self.cert_info())

    # ---------------------------------------------------------------- settings

    async def get_settings(self, request: web.Request) -> web.Response:
        return web.json_response({
            "values": {k: self.cfg.get(k, d) for k, d in SETTINGS.items()},
            "running": self.running,
        })

    async def save_settings(self, request: web.Request) -> web.Response:
        body = await request.json()
        new = {k: self.cfg.get(k, d) for k, d in SETTINGS.items()}
        for key, default in SETTINGS.items():
            if key not in body:
                continue
            value = body[key]
            if isinstance(default, bool):
                if not isinstance(value, bool):
                    raise web.HTTPBadRequest(text=f"{key} must be true or false.")
            else:
                value = str(value or "").strip()
                if key in CHOICES and value not in CHOICES[key]:
                    raise web.HTTPBadRequest(text=f"{key} must be one of {', '.join(CHOICES[key])}.")
            new[key] = value
            self.cfg[key] = value
        self._save_cfg()
        log.info("settings saved: %s", ", ".join(f"{k}={v}" for k, v in new.items() if v != self.running.get(k)) or "no change")
        return web.json_response({"ok": True})

    # ---------------------------------------------------------------- app

    async def index(self, request: web.Request) -> web.FileResponse:
        return web.FileResponse(STATIC / "index.html", headers={"Cache-Control": "no-store"})

    def app(self) -> web.Application:
        app = web.Application(middlewares=[self.auth], client_max_size=1024 * 1024)
        app.add_routes([
            web.get("/", self.index),
            web.get("/api/status", self.status),
            web.get("/api/logs", self.logs),
            web.get("/api/printers", self.list_printers),
            web.post("/api/printers", self.save_printer),
            web.delete("/api/printers/{serial}", self.delete_printer),
            web.post("/api/restart", self.restart),
            web.post("/api/certs", self.upload_certs),
            web.get("/api/settings", self.get_settings),
            web.post("/api/settings", self.save_settings),
            web.post("/api/debug", self.debug_toggle),
            web.get("/api/diagnostics", self.diagnostics),
        ])
        return app


async def start(admin: Admin, host: str, port: int) -> web.AppRunner:
    runner = web.AppRunner(admin.app(), access_log=None)
    await runner.setup()
    await web.TCPSite(runner, host, port).start()
    log.info("admin page on http://%s:%d/", host, port)
    return runner
