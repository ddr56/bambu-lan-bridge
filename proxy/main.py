"""bambu-lan-bridge entry point: python -m proxy.main [config.yaml]

A LAN-only signing proxy. Each printer is presented as a virtual LAN-mode
device; clients connect to it, send plain commands, and the proxy signs the
privileged ones with the app certificate you provide, so a cloud-bound printer
accepts them without Developer Mode. No Bambu cloud account is used.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
import signal
import subprocess
import sys
from pathlib import Path

import yaml

from . import __version__, discovery, relay, ssdp, tls, web
from .logbuf import RingHandler
from .mqtt_server import MqttServer
from .router import Router
from .signer import Signer
from .upstream import LanLink

log = logging.getLogger("proxy")


def add_addresses(ips: list[str], dev: str, prefix: int) -> list[str]:
    """Put every virtual IP on dev (needs NET_ADMIN). Returns the ones we added."""
    have = subprocess.run(["ip", "-4", "-o", "addr", "show", "dev", dev], capture_output=True, text=True).stdout
    added = []
    for ip in ips:
        if f" {ip}/" not in have:
            subprocess.run(["ip", "addr", "add", f"{ip}/{prefix}", "dev", dev], check=True)
            added.append(f"{ip}/{prefix}")
            log.info("added %s/%d on %s", ip, prefix, dev)
    return added


def remove_addresses(addrs: list[str], dev: str) -> None:
    for a in addrs:
        subprocess.run(["ip", "addr", "del", a, "dev", dev])
        log.info("removed %s from %s", a, dev)


DEFAULT_PASSTHROUGH = [990, "50000-50100", 6000, 322]


def expand_ports(spec: list) -> list[int]:
    """[990, "50000-50100"] -> [990, 50000, ..., 50100]"""
    ports = []
    for item in spec:
        if isinstance(item, str) and "-" in item:
            lo, hi = (int(x) for x in item.split("-", 1))
            ports.extend(range(lo, hi + 1))
        else:
            ports.append(int(item))
    return ports


def virtual_serial(serial: str) -> str:
    """Same length and model prefix (094 = H2D, 31B = H2C), 4th character set to V.

    Slicers key devices on the serial, so announcing the real one next to the
    real printer makes the entry flip between the two IPs.
    """
    return serial[:3] + "V" + serial[4:]


async def run(cfg_path: Path, cfg: dict, logbuf: RingHandler) -> None:
    loop = asyncio.get_running_loop()
    data = Path(cfg.get("data_dir", "data"))
    data.mkdir(parents=True, exist_ok=True)
    printers = [dict(p) for p in cfg.get("printers") or []]
    ips = [p["virtual_ip"] for p in printers]
    for ip in ips:
        ipaddress.ip_address(ip)

    dev = os.environ.get("PROXY_INTERFACE", "eth0")
    added = []
    if os.environ.get("PROXY_ADD_ADDRESSES") == "1":
        added = add_addresses(ips, dev, int(os.environ.get("PROXY_PREFIX", "32")))
    try:
        await serve(cfg_path, cfg, loop, data, printers, ips, logbuf)
    finally:
        remove_addresses(added, dev)


async def serve(cfg_path: Path, cfg: dict, loop, data: Path, printers: list[dict], ips: list[str],
                logbuf: RingHandler) -> None:
    log.info("bambu-lan-bridge %s, %d printer(s)", __version__, len(printers))
    tls_ctx = tls.ensure(data / "proxy-tls", ips) if ips else None
    routers: dict[str, Router] = {}

    mode = cfg.get("mode", "full")
    certs = Path(cfg.get("certs_dir", data / "certs"))

    signer = None
    if mode != "read_only":
        try:
            signer = Signer(certs)
            log.info("signing with %s (cert valid until %s)", certs, signer.not_after.date())
        except (OSError, ValueError) as e:
            log.warning("no signing certificate in %s (%s): running read-only until one is uploaded", certs, e)

    for p in printers:
        serial = p["serial"]
        p.setdefault("virtual_serial", virtual_serial(serial))
        server = MqttServer(serial, str(p["access_code"]), on_request=None, virtual_serial=p["virtual_serial"])
        if not p.get("lan_ip"):
            log.warning("%s: no printer IP set, so it can't be reached; add its LAN IP on the admin page", serial)
        lan = None
        if p.get("lan_ip"):
            lan = LanLink(loop, serial, p["lan_ip"], str(p["access_code"]),
                          on_report=lambda payload, s=serial: routers[s].on_lan_report(payload),
                          on_connect=lambda s=serial: routers[s].upstream_connected("lan"))
        routers[serial] = Router(serial, server, lan, signer, mode)
        routers[serial].name = p.get("name", serial)
        # The proxy signs for clients, so present the printer as LAN-developer-mode:
        # clients then send plain commands and skip the signing a secured printer needs.
        routers[serial].dev_mode_present = mode == "full" and bool(cfg.get("present_developer_mode", True))
        await server.start(p.get("bind", p["virtual_ip"]), int(cfg.get("mqtt_port", 8883)), tls_ctx)
        if lan:
            lan.start()
        if p.get("lan_ip"):
            # Services passed straight to the printer, which answers with its own TLS:
            # FTPS (990 plus vsftpd's 50000-50100 passive range), file browsing (6000)
            # and RTSPS camera (322). Not 3002: stock Studio stays on its cloud login.
            ports = expand_ports(p.get("passthrough_ports", cfg.get("passthrough_ports", DEFAULT_PASSTHROUGH)))
            started = 0
            for port in ports:
                try:
                    await relay.start(p["virtual_serial"], p.get("bind", p["virtual_ip"]), p["lan_ip"], port,
                                      quiet=port >= 50000)
                    started += 1
                except OSError as e:
                    log.warning("%s: relay on port %s not started: %s", serial, port, e)
            log.info("%s: relaying %d of %d ports to %s", serial, started, len(ports), p["lan_ip"])

    tasks = []
    if cfg.get("ssdp", True) and printers:
        tasks.append(asyncio.create_task(ssdp.announce(printers, cfg.get("ssdp_target", "255.255.255.255"))))
    found = await discovery.listen({p["virtual_serial"] for p in printers}) if cfg.get("discovery", True) else None

    stop = asyncio.Event()
    if hasattr(signal, "SIGTERM"):
        try:
            loop.add_signal_handler(signal.SIGTERM, stop.set)
        except NotImplementedError:  # Windows
            pass
    admin = web.Admin(cfg_path, cfg, data, certs, routers, printers, found, logbuf, stop)
    runner = await web.start(admin, cfg.get("admin_bind", "0.0.0.0"), int(cfg.get("admin_port", 8099)))
    await stop.wait()
    log.info("stopping")
    await runner.cleanup()
    for t in tasks:
        t.cancel()
    for r in routers.values():
        if r.lan:
            r.lan.stop()


def main() -> None:
    logbuf = RingHandler()
    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"),
                        format="%(asctime)s %(levelname)-7s %(name)-9s %(message)s")
    logbuf.setFormatter(logging.Formatter("%(asctime)s %(levelname)-7s %(name)-9s %(message)s", "%H:%M:%S"))
    logbuf.setLevel(logging.INFO)
    logging.getLogger().addHandler(logbuf)
    path = Path(sys.argv[1] if len(sys.argv) > 1 else os.environ.get("PROXY_CONFIG", "data/config.yaml"))
    if path.exists():
        cfg = yaml.safe_load(path.read_text()) or {}
    else:
        # First start: an empty config the admin page fills in.
        cfg = {"data_dir": str(path.parent), "ssdp": True, "mode": "full", "printers": []}
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(yaml.safe_dump(cfg, sort_keys=False))
        log.info("no config at %s: started empty, add printers on the admin page", path)
    try:
        asyncio.run(run(path, cfg, logbuf))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
