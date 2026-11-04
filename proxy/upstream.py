"""Upstream MQTT link: one LAN link per printer to the real printer.

paho runs its own network thread; reports are handed to the asyncio loop with
call_soon_threadsafe so the rest of the proxy stays single-threaded.
"""

from __future__ import annotations

import asyncio
import logging
import random
import ssl
import time
from typing import Callable

import paho.mqtt.client as mqtt

log = logging.getLogger("upstream")


def _client(name: str, user: str, password: str, verify_tls: bool) -> mqtt.Client:
    c = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=f"{name}-{random.randint(0, 99999)}")
    c.username_pw_set(user, password)
    ctx = ssl.create_default_context()
    if not verify_tls:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    c.tls_set_context(ctx)
    c.reconnect_delay_set(2, 60)
    return c


class LanLink:
    """bblp/<access code> to the real printer's port 8883."""

    def __init__(self, loop: asyncio.AbstractEventLoop, serial: str, host: str, code: str,
                 on_report: Callable[[bytes], None], on_connect: Callable[[], None] | None = None) -> None:
        self.serial, self.host = serial, host
        self.connected = False
        self.last_rx = 0.0
        self._loop, self._on_report, self._on_connect_cb = loop, on_report, on_connect
        self.client = _client("proxy-lan", "bblp", code, verify_tls=False)
        self.client.on_connect = self._on_connect
        self.client.on_disconnect = self._on_disconnect
        self.client.on_message = self._on_message

    def start(self) -> None:
        self.client.connect_async(self.host, 8883, keepalive=30)
        self.client.loop_start()

    def stop(self) -> None:
        self.client.loop_stop()
        self.client.disconnect()

    def fresh(self, max_age: float = 30) -> bool:
        return self.connected and time.monotonic() - self.last_rx < max_age

    def publish(self, payload: str | bytes) -> None:
        self.client.publish(f"device/{self.serial}/request", payload)

    def _on_connect(self, client, userdata, flags, rc, props) -> None:
        if rc.is_failure:
            log.warning("%s: LAN %s refused: %s", self.serial, self.host, rc)
            return
        self.connected = True
        log.info("%s: LAN connected to %s", self.serial, self.host)
        client.subscribe(f"device/{self.serial}/report")
        if self._on_connect_cb:
            self._loop.call_soon_threadsafe(self._on_connect_cb)

    def _on_disconnect(self, client, userdata, flags, rc, props) -> None:
        if self.connected:
            log.warning("%s: LAN disconnected: %s", self.serial, rc)
        self.connected = False

    def _on_message(self, client, userdata, msg) -> None:
        self.last_rx = time.monotonic()
        self._loop.call_soon_threadsafe(self._on_report, msg.payload)
