"""Raw TCP passthrough from a virtual IP port to the same port on the real printer.

Used for services the proxy does not emulate: the slicer bind/detect handshake
(3000/3002) now, camera (322) and file browsing (6000) later. Bytes are not
inspected, so the printer's own TLS and serial go through unchanged.
"""

from __future__ import annotations

import asyncio
import logging

log = logging.getLogger("relay")


async def _pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> int:
    total = 0
    try:
        while data := await reader.read(65536):
            total += len(data)
            writer.write(data)
            await writer.drain()
    except (ConnectionError, OSError):
        pass
    finally:
        try:
            writer.write_eof()
        except (OSError, RuntimeError):
            writer.close()
    return total


async def start(name: str, bind_ip: str, target_ip: str, port: int,
                quiet: bool = False) -> asyncio.base_events.Server:
    async def handle(c_reader: asyncio.StreamReader, c_writer: asyncio.StreamWriter) -> None:
        peer = "%s:%s" % c_writer.get_extra_info("peername")[:2]
        try:
            p_reader, p_writer = await asyncio.wait_for(asyncio.open_connection(target_ip, port), 5)
        except (OSError, asyncio.TimeoutError) as e:
            log.warning("%s: %s -> %s:%d failed: %s", name, peer, target_ip, port, e or type(e).__name__)
            c_writer.close()
            return
        up, down = await asyncio.gather(_pipe(c_reader, p_writer), _pipe(p_reader, c_writer))
        p_writer.close()
        c_writer.close()
        (log.debug if quiet else log.info)("%s: %s <-> :%d done (%d bytes up, %d down)", name, peer, port, up, down)

    server = await asyncio.start_server(handle, bind_ip, port)
    log.debug("%s: relay %s:%d -> %s:%d", name, bind_ip, port, target_ip, port)
    return server
