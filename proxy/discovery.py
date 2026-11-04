"""Listen for Bambu printers announcing themselves (SSDP NOTIFY on UDP 2021).

Gives the admin page a list of printers on the LAN with their IP, model code
and firmware version, to add as virtual printers in one click.
"""

from __future__ import annotations

import asyncio
import logging
import socket
import time

log = logging.getLogger("discovery")


class Discovery(asyncio.DatagramProtocol):
    def __init__(self, ignore: set[str]) -> None:
        self.ignore = ignore          # our own virtual serials
        self.seen: dict[str, dict] = {}

    def datagram_received(self, data: bytes, addr) -> None:
        if not data.startswith(b"NOTIFY"):
            return
        fields = {}
        for line in data.decode(errors="replace").split("\r\n")[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                fields[k.strip().lower()] = v.strip()
        serial = fields.get("usn")
        # Proxies (this one or another instance) announce firmware 00.00.00.00; real printers never do.
        if not serial or serial in self.ignore or fields.get("devversion.bambu.com") == "00.00.00.00":
            return
        self.seen[serial] = {
            "serial": serial,
            "ip": fields.get("location", addr[0]),
            "name": fields.get("devname.bambu.com", ""),
            "model_code": fields.get("devmodel.bambu.com", ""),
            "firmware": fields.get("devversion.bambu.com", ""),
            "connect": fields.get("devconnect.bambu.com", ""),
            "bind": fields.get("devbind.bambu.com", ""),
            "last_seen": time.time(),
        }

    def printers(self) -> list[dict]:
        now = time.time()
        return sorted((dict(p, age=round(now - p["last_seen"])) for p in self.seen.values()
                       if now - p["last_seen"] < 600), key=lambda p: p["name"])


async def listen(ignore: set[str]) -> Discovery | None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind(("", 2021))
    except OSError as e:
        log.warning("not listening for printers on UDP 2021: %s", e)
        return None
    _, proto = await asyncio.get_running_loop().create_datagram_endpoint(lambda: Discovery(ignore), sock=sock)
    log.info("listening for printer announcements on UDP 2021")
    return proto
