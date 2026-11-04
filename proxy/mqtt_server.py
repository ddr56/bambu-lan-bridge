"""Minimal MQTT 3.1.1 server over TLS, one per virtual printer.

Only what LAN clients use: CONNECT (user bblp + access code), SUBSCRIBE,
UNSUBSCRIBE, PUBLISH at QoS 0/1, PINGREQ and DISCONNECT. No retained messages,
no sessions, no wills. Everything the listener hands out is pinned to one serial.
"""

from __future__ import annotations

import asyncio
import logging
import ssl
from typing import Awaitable, Callable

log = logging.getLogger("mqtt")

CONNECT, CONNACK, PUBLISH, PUBACK, SUBSCRIBE, SUBACK = 1, 2, 3, 4, 8, 9
UNSUBSCRIBE, UNSUBACK, PINGREQ, PINGRESP, DISCONNECT = 10, 11, 12, 13, 14


def _varint(n: int) -> bytes:
    out = bytearray()
    while True:
        b, n = n & 0x7F, n >> 7
        out.append(b | (0x80 if n else 0))
        if not n:
            return bytes(out)


def _str(s: str | bytes) -> bytes:
    b = s.encode() if isinstance(s, str) else s
    return len(b).to_bytes(2, "big") + b


def _packet(kind: int, flags: int, body: bytes) -> bytes:
    return bytes([kind << 4 | flags]) + _varint(len(body)) + body


def topic_matches(pattern: str, topic: str) -> bool:
    p, t = pattern.split("/"), topic.split("/")
    for i, part in enumerate(p):
        if part == "#":
            return True
        if i >= len(t) or (part != "+" and part != t[i]):
            return False
    return len(p) == len(t)


class _Reader:
    def __init__(self, data: bytes) -> None:
        self.data, self.pos = data, 0

    def u8(self) -> int:
        self.pos += 1
        return self.data[self.pos - 1]

    def u16(self) -> int:
        self.pos += 2
        return int.from_bytes(self.data[self.pos - 2:self.pos], "big")

    def bytes_(self) -> bytes:
        n = self.u16()
        self.pos += n
        return self.data[self.pos - n:self.pos]

    def str_(self) -> str:
        return self.bytes_().decode(errors="replace")

    def rest(self) -> bytes:
        return self.data[self.pos:]


class Client:
    def __init__(self, writer: asyncio.StreamWriter, peer: str) -> None:
        self.writer = writer
        self.peer = peer
        self.subs: set[str] = set()

    def send(self, data: bytes) -> None:
        if not self.writer.is_closing():
            self.writer.write(data)


class MqttServer:
    """Accepts LAN clients for one printer.

    The printer answers to its virtual serial (what discovery announces) and,
    for clients set up before virtual serials existed, its real one. Reports go
    out on whichever topic the client subscribed to; with the virtual topic the
    real serial inside the payload is swapped for the virtual one too.

    on_request(payload) is called for every PUBLISH to device/<either>/request.
    publish_report(payload) fans a report out to subscribed clients.
    """

    def __init__(self, serial: str, access_code: str, on_request: Callable[[bytes], Awaitable[None]],
                 virtual_serial: str | None = None) -> None:
        self.serial = virtual_serial or serial
        self.real_serial = serial
        self.access_code = access_code
        self.on_request = on_request
        self.report_topic = f"device/{self.serial}/report"
        self.real_report_topic = f"device/{serial}/report"
        self.request_topics = {f"device/{self.serial}/request", f"device/{serial}/request"}
        self.clients: set[Client] = set()

    async def start(self, host: str, port: int, tls: ssl.SSLContext) -> asyncio.base_events.Server:
        server = await asyncio.start_server(self._handle, host, port, ssl=tls)
        log.info("%s: MQTT on %s:%d", self.serial, host, port)
        return server

    def publish_report(self, payload: bytes) -> None:
        virtual = real = None
        for c in list(self.clients):
            if any(topic_matches(s, self.report_topic) for s in c.subs):
                if virtual is None:
                    body = payload.replace(self.real_serial.encode(), self.serial.encode())
                    virtual = _packet(PUBLISH, 0, _str(self.report_topic) + body)
                c.send(virtual)
            elif any(topic_matches(s, self.real_report_topic) for s in c.subs):
                real = real or _packet(PUBLISH, 0, _str(self.real_report_topic) + payload)
                c.send(real)

    async def _read_packet(self, reader: asyncio.StreamReader) -> tuple[int, int, bytes]:
        first = (await reader.readexactly(1))[0]
        length, shift = 0, 0
        while True:
            b = (await reader.readexactly(1))[0]
            length |= (b & 0x7F) << shift
            shift += 7
            if not b & 0x80:
                break
        return first >> 4, first & 0x0F, await reader.readexactly(length)

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = "%s:%s" % writer.get_extra_info("peername")[:2]
        client = Client(writer, peer)
        try:
            kind, _, body = await asyncio.wait_for(self._read_packet(reader), 10)
            if kind != CONNECT or not self._accept(body, client):
                return
            self.clients.add(client)
            log.info("%s: client %s connected (%d)", self.serial, peer, len(self.clients))
            while True:
                kind, flags, body = await asyncio.wait_for(self._read_packet(reader), 300)
                if kind == PUBLISH:
                    await self._on_publish(client, flags, body)
                elif kind == SUBSCRIBE:
                    r = _Reader(body)
                    pid = r.u16()
                    granted = bytearray()
                    while r.pos < len(body):
                        client.subs.add(r.str_())
                        granted.append(min(r.u8(), 0))  # we only deliver QoS 0
                    client.send(_packet(SUBACK, 0, pid.to_bytes(2, "big") + bytes(granted)))
                elif kind == UNSUBSCRIBE:
                    r = _Reader(body)
                    pid = r.u16()
                    while r.pos < len(body):
                        client.subs.discard(r.str_())
                    client.send(_packet(UNSUBACK, 0, pid.to_bytes(2, "big")))
                elif kind == PINGREQ:
                    client.send(_packet(PINGRESP, 0, b""))
                elif kind == DISCONNECT:
                    return
                await writer.drain()
        except ssl.SSLError as e:
            # A client that verifies the proxy's cert (signed by our own CA, not the
            # printer's) fails here; visible when debug logging is on.
            log.debug("%s: client %s TLS error: %s", self.serial, peer, e)
        except (asyncio.IncompleteReadError, asyncio.TimeoutError, ConnectionError):
            pass
        except Exception:  # noqa: BLE001
            log.exception("%s: client %s", self.serial, peer)
        finally:
            if client in self.clients:
                self.clients.discard(client)
                log.info("%s: client %s left (%d)", self.serial, peer, len(self.clients))
            writer.close()

    def _accept(self, body: bytes, client: Client) -> bool:
        r = _Reader(body)
        r.str_()  # protocol name
        r.u8()    # level
        flags = r.u8()
        r.u16()   # keepalive
        r.str_()  # client id
        if flags & 0x04:
            r.str_()
            r.bytes_()
        user = r.str_() if flags & 0x80 else ""
        password = r.bytes_().decode(errors="replace") if flags & 0x40 else ""
        ok = user == "bblp" and password == self.access_code
        client.send(_packet(CONNACK, 0, bytes([0, 0 if ok else 5])))
        if not ok:
            log.warning("%s: refused %s (user %r)", self.serial, client.peer, user)
        return ok

    async def _on_publish(self, client: Client, flags: int, body: bytes) -> None:
        qos = (flags >> 1) & 3
        r = _Reader(body)
        topic = r.str_()
        if qos:
            client.send(_packet(PUBACK, 0, r.u16().to_bytes(2, "big")))
        if topic in self.request_topics:
            await self.on_request(r.rest())
        else:
            log.warning("%s: %s published to %s, dropped", self.serial, client.peer, topic)
