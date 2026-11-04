"""Announce each virtual printer the way a Bambu printer does: SSDP NOTIFY broadcast to UDP 2021.

Fields copied from real H2C/H2D announcements. DevConnect "lan" plus DevBind
"bind" is what the original proxy sends; a printer in cloud mode says
"cloud"/"occupied", which slicers do not offer as a LAN printer.
"""

from __future__ import annotations

import asyncio
import logging
import socket

log = logging.getLogger("ssdp")

INTERVAL = 5


def notify(serial: str, name: str, model_code: str, ip: str) -> bytes:
    lines = [
        "NOTIFY * HTTP/1.1",
        "HOST: 239.255.255.250:1990",
        "Server: UPnP/1.0",
        f"Location: {ip}",
        "NT: urn:bambulab-com:device:3dprinter:1",
        "NTS: ssdp:alive",
        f"USN: {serial}",
        "Cache-Control: max-age=1800",
        f"DevModel.bambu.com: {model_code}",
        f"DevName.bambu.com: {name}",
        "DevSignal.bambu.com: -40",
        "DevConnect.bambu.com: lan",
        "DevBind.bambu.com: bind",
        "Devseclink.bambu.com: secure",
        "DevVersion.bambu.com: 00.00.00.00",
        "DevCap.bambu.com: 1",
    ]
    return ("\r\n".join(lines) + "\r\n\r\n").encode()


async def announce(printers: list[dict], target: str = "255.255.255.255") -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    packets = [notify(p.get("virtual_serial", p["serial"]), p.get("virtual_name", p["name"] + " (proxy)"),
                      p["model_code"], p["virtual_ip"]) for p in printers]
    log.info("announcing %d printer(s) to %s:2021 every %d s", len(packets), target, INTERVAL)
    while True:
        for pkt in packets:
            try:
                sock.sendto(pkt, (target, 2021))
            except OSError as e:
                log.warning("send failed: %s", e)
        await asyncio.sleep(INTERVAL)
