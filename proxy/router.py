"""Per-printer routing between the virtual LAN endpoint and the real printer.

Reports from the printer go straight back to the connected clients. Requests go
to the printer over LAN when it is up. In mode "read_only" anything that would
change the printer is dropped. In mode "full" print.* frames are signed with the
app identity (frames a client already signed pass untouched), after installing
the app certificate once per LAN connection.
"""

from __future__ import annotations

import asyncio
import collections
import json
import logging
import re
import time

from .mqtt_server import MqttServer
from .signer import ENCRYPTED_FIELDS, SequenceIds, Signer, encrypt_field, needs_signature, printer_public_key
from .upstream import LanLink

log = logging.getLogger("router")

READ_ONLY = {
    "pushing": {"pushall", "start", "stop"},
    "print": {"pushall", "get_version", "get_access_code"},
    "info": None,   # every info.* command is a query
}

CERT_ACK_TIMEOUT = 8

# The printer's `fun` bitmask, as "fun":"<hex>" or "fun":<decimal>; bit 0x20000000
# set means LAN developer mode is off (commands must be signed/encrypted).
_FUN_RE = re.compile(rb'("fun"\s*:\s*)(?:"([0-9A-Fa-f]+)"|(\d+))')


_STATE_RE = re.compile(rb'"gcode_state"\s*:\s*"([A-Z_]+)"')


def _clear_fun_bit(m: "re.Match") -> bytes:
    if m.group(2) is not None:  # "fun":"<hex>"
        n = int(m.group(2), 16) & ~0x20000000
        return m.group(1) + b'"' + format(n, "X").encode() + b'"'
    n = int(m.group(3)) & ~0x20000000   # "fun":<decimal>
    return m.group(1) + str(n).encode()


def is_read_only(frame: dict) -> bool:
    for section, body in frame.items():
        if section == "header":
            continue
        if section not in READ_ONLY or not isinstance(body, dict):
            return False
        allowed = READ_ONLY[section]
        if allowed is not None and body.get("command") not in allowed:
            return False
    return bool(frame)


class Router:
    def __init__(self, serial: str, server: MqttServer, lan: LanLink | None,
                 signer: Signer | None = None, mode: str = "full") -> None:
        self.serial, self.server, self.lan = serial, server, lan
        self.signer = signer
        self.mode = mode if signer else "read_only"
        self.seq = SequenceIds()
        # The printer keeps the app cert in RAM; install it once per LAN connection.
        self.cert_ok = {"lan": False}
        self._cert_lock = {"lan": asyncio.Lock()}
        self._pending: dict[str, asyncio.Future] = {}
        self.printer_key = None  # from the printer_cert in the app_cert_install answer
        # Our sequence_id -> (command, sent at, client's sequence_id) for signed commands.
        self._sent: dict[str, tuple[str, float, object]] = {}
        # Our sequence_id -> future, for admin-initiated commands awaiting the printer's answer.
        self._waiters: dict[str, asyncio.Future] = {}
        # Recent non-status commands for the admin page.
        self.recent: collections.deque[dict] = collections.deque(maxlen=10)
        self.name = serial
        self.dev_mode_present = False   # set by main: present LAN developer mode to clients
        self.ams_units: int | None = None   # learned from reports
        self.nozzle_diameter: str = ""       # learned from reports
        self.gcode_state: str = ""           # learned from reports
        self.trays: dict = {}                # "ams:slot" -> loaded filament, learned from reports
        self.last_report: bytes = b""        # last full pushall, for the diagnostics snapshot
        server.on_request = self.on_request

    def status(self) -> dict:
        lan = self.lan
        lan_status = None if lan is None else {
            "ip": lan.host, "connected": lan.connected,
            "last_report_s": round(time.monotonic() - lan.last_rx) if lan.last_rx else None}
        return {
            "route": self.route(),
            "mode": self.mode,
            "lan": lan_status,
            "clients": [c.peer for c in self.server.clients],
            "cert_installed": dict(self.cert_ok),
            "printer_key": self.printer_key is not None,
            "recent": list(self.recent)[::-1],
            "nozzle": self.nozzle_diameter,
            "state": self.gcode_state,
            "ams_units": self.ams_units,
            "trays": list(self.trays.values()),
        }

    def upstream_connected(self, route: str) -> None:
        self.cert_ok[route] = False

    def on_lan_report(self, payload: bytes) -> None:
        if log.isEnabledFor(logging.DEBUG):
            log.debug("%s: lan report %s", self.serial, payload.decode("utf-8", "replace")[:4000])
        self._learn_ams(payload)
        payload = self._answer(payload)
        if not self._own_ack(payload):
            self.server.publish_report(self._present_dev_mode(payload))

    def _learn_ams(self, payload: bytes) -> None:
        """Track light printer metadata from reports: the print state (cheap regex, every
        report) and, from a full AMS report, the unit count, nozzle diameter and the
        per-slot loaded filament, for the admin page."""
        m = _STATE_RE.search(payload)
        if m:
            self.gcode_state = m.group(1).decode()
        if b'"tray_info_idx"' not in payload:   # only full AMS reports carry the trays
            return
        self.last_report = payload[:65536]      # keep the latest full pushall for diagnostics
        try:
            pr = json.loads(payload).get("print", {})
        except ValueError:
            return
        units = pr.get("ams", {}).get("ams") if isinstance(pr.get("ams"), dict) else None
        if not isinstance(units, list) or not units:
            return
        self.ams_units = len(units)
        if pr.get("nozzle_diameter"):
            self.nozzle_diameter = str(pr["nozzle_diameter"])
        trays = {}
        for unit in units:
            aid = unit.get("id")
            for tray in unit.get("tray") or []:
                if tray.get("tray_info_idx") or tray.get("tray_type"):
                    trays[f"{aid}:{tray.get('id')}"] = {
                        "ams_id": aid, "slot_id": tray.get("id"),
                        "tray_info_idx": tray.get("tray_info_idx") or "",
                        "tray_type": tray.get("tray_type") or "",
                        "tray_color": tray.get("tray_color") or "",
                        "setting_id": tray.get("setting_id") or ""}
        self.trays = trays

    def _present_dev_mode(self, payload: bytes) -> bytes:
        """Make clients see LAN developer mode as on. The proxy signs their commands
        anyway, so they can send cleartext and skip the signing a secured printer
        needs. Clears the "developer mode off" bit (0x20000000) in the printer's `fun`
        field (a hex string on H2, else a decimal number), and drops the "MQTT verify
        failed" HMS (0500050000010007) which a client would otherwise latch into
        "must encrypt" even though we present developer mode."""
        if not self.dev_mode_present:
            return payload
        if b'"hms"' in payload and b"65543" in payload:
            payload = self._drop_verify_hms(payload)
        if b'"fun"' in payload:
            payload = _FUN_RE.sub(_clear_fun_bit, payload)
        return payload

    def _drop_verify_hms(self, payload: bytes) -> bytes:
        try:
            data = json.loads(payload)
        except ValueError:
            return payload
        body = data.get("print") if isinstance(data.get("print"), dict) else data
        hms = body.get("hms") if isinstance(body, dict) else None
        if not isinstance(hms, list):
            return payload
        kept = [h for h in hms if not (isinstance(h, dict)
                                       and h.get("attr") == 0x05000500 and h.get("code") == 0x00010007)]
        if len(kept) == len(hms):
            return payload
        body["hms"] = kept
        log.info("%s: hid the MQTT-verify-failed HMS from clients (developer mode is presented)", self.serial)
        return json.dumps(data, separators=(",", ":")).encode()

    def _answer(self, payload: bytes) -> bytes:
        """Log the printer's answer to a signed command and give it back the client's sequence_id."""
        if not self._sent or b'"sequence_id"' not in payload:
            return payload
        now = time.monotonic()
        for seq, (_, at, _) in list(self._sent.items()):
            if now - at > 60:
                del self._sent[seq]
        try:
            body = json.loads(payload).get("print", {})
        except ValueError:
            return payload
        seq = str(body.get("sequence_id")) if isinstance(body, dict) else None
        sent = self._sent.pop(seq, None)
        if not sent:
            return payload
        command, _, client_seq = sent
        log.info("%s: %s answered: result=%s reason=%s err_code=%s", self.serial, command,
                 body.get("result"), body.get("reason"), body.get("err_code"))
        result, reason, err = str(body.get("result") or ""), str(body.get("reason") or ""), body.get("err_code")
        answer = result + (f": {reason}" if reason and reason.lower() != result.lower() else "") + (f" ({err})" if err else "")
        for entry in self.recent:
            if entry.get("seq") == seq:
                entry["answer"] = answer
        waiter = self._waiters.pop(seq, None)   # an admin command awaiting its answer
        if waiter and not waiter.done():
            waiter.set_result(dict(body))
        if client_seq is None:
            return payload   # admin command: no client sequence_id to restore
        return re.sub(rb'"sequence_id"\s*:\s*(?:"' + seq.encode() + rb'"|' + seq.encode() + rb'(?![0-9]))',
                      b'"sequence_id":' + json.dumps(client_seq).encode(), payload, count=1)

    def _own_ack(self, payload: bytes) -> bool:
        """Resolve and swallow the answer to an app_cert_install the proxy sent."""
        if not self._pending or b"app_cert_install" not in payload:
            return False
        try:
            body = json.loads(payload).get("security", {})
        except ValueError:
            return False
        fut = self._pending.get(str(body.get("sequence_id")))
        if fut is None:
            return False
        ok = str(body.get("result", "")).upper() == "SUCCESS" and bool(body.get("printer_cert"))
        if ok:
            try:
                self.printer_key = printer_public_key(body["printer_cert"])
                log.debug("%s: printer key cached (RSA-%d)", self.serial, self.printer_key.key_size)
            except ValueError as e:
                log.warning("%s: unreadable printer_cert: %s", self.serial, e)
        if not fut.done():
            fut.set_result(ok)
        return True

    def route(self) -> str | None:
        if self.lan and self.lan.connected:
            return "lan"
        return None

    def _send(self, route: str, payload: str | bytes) -> None:
        self.lan.publish(payload)

    async def _ensure_cert(self, route: str) -> None:
        async with self._cert_lock[route]:
            if self.cert_ok[route]:
                return
            seq = self.seq.take()
            fut = asyncio.get_running_loop().create_future()
            self._pending[seq] = fut
            self._send(route, self.signer.cert_install(seq))
            try:
                ok = await asyncio.wait_for(fut, CERT_ACK_TIMEOUT)
            except asyncio.TimeoutError:
                ok = False
            finally:
                self._pending.pop(seq, None)
            # Send the command either way: a printer that already trusts the
            # cert still accepts it, and the client sees the printer's answer.
            self.cert_ok[route] = ok
            log.info("%s: app_cert_install via %s: %s", self.serial, route, "SUCCESS" if ok else "no success ack")

    async def on_request(self, payload: bytes) -> None:
        if log.isEnabledFor(logging.DEBUG):
            log.debug("%s: client-> %s", self.serial, payload.decode("utf-8", "replace")[:4000])
        try:
            frame = json.loads(payload)
        except ValueError:
            log.warning("%s: request is not JSON, dropped", self.serial)
            return
        if not isinstance(frame, dict) or not frame:
            return
        if self.mode == "read_only" and not is_read_only(frame):
            log.info("%s: dropped (read-only): %s", self.serial, _summary(frame))
            return
        via = self.route()
        if via is None:
            log.warning("%s: no upstream for %s", self.serial, _summary(frame))
            return

        wire: str | bytes = payload
        body = frame.get("print")
        if needs_signature(frame):
            dropped = [k for k in frame if k != "print"]
            if dropped:
                log.warning("%s: unsigned extra sections %s dropped from signed frame", self.serial, dropped)
            body = frame["print"]
            # The printer refuses signed frames with a small sequence_id (0 and 1 get
            # "verify failed", 84033545), and clients such as Bambuddy count from 0.
            # Send our own id and hand the client's back in the answer.
            client_seq = body.get("sequence_id")
            body["sequence_id"] = self.seq.take()
            self._sent[body["sequence_id"]] = (_summary(frame), time.monotonic(), client_seq)
            # The printer checks md5 on a print from its storage; Studio sends this literal.
            if body.get("command") == "project_file" and not body.get("md5"):
                body["md5"] = "from_sd_card"
            field = ENCRYPTED_FIELDS.get(body.get("command"))
            if field in body and self.printer_key is None:
                self.cert_ok[via] = False  # the install answer carries the printer's key
            await self._ensure_cert(via)
            if field in body and self.printer_key is not None:
                # Secured firmware wants this field encrypted to the printer and the
                # cleartext gone.
                body[field + "_enc"] = encrypt_field(self.printer_key, str(body.pop(field)))
            wire = self.signer.envelope(body)
            log.info("%s: %s via %s (signed, seq %s for %s) %s", self.serial, _summary(frame), via,
                     body["sequence_id"], client_seq, _args(body))
            self.recent.append({"at": time.time(), "command": _summary(frame), "via": via, "signed": True,
                                "seq": body["sequence_id"], "answer": None})
        elif is_read_only(frame):
            log.debug("%s: %s via %s", self.serial, _summary(frame), via)
        else:
            log.info("%s: %s via %s", self.serial, _summary(frame), via)
            self.recent.append({"at": time.time(), "command": _summary(frame), "via": via, "signed": False,
                                "seq": None, "answer": None})
        if log.isEnabledFor(logging.DEBUG):
            log.debug("%s: %s-> %s", self.serial, via,
                      (wire if isinstance(wire, str) else wire.decode("utf-8", "replace"))[:4000])
        self._send(via, wire)

    async def command(self, body: dict, timeout: float = 8.0) -> dict:
        """Sign and send an admin-initiated print.* command (e.g. ams_filament_setting),
        then wait for and return the printer's answer. Used by the admin API."""
        if self.mode != "full":
            return {"result": "FAIL", "reason": "the proxy is read-only; no signing key set"}
        via = self.route()
        if via is None:
            return {"result": "FAIL", "reason": "the printer is not reachable"}
        body = dict(body)
        seq = self.seq.take()
        body["sequence_id"] = seq
        frame = {"print": body}
        fut = asyncio.get_running_loop().create_future()
        self._waiters[seq] = fut
        self._sent[seq] = (_summary(frame), time.monotonic(), None)
        try:
            field = ENCRYPTED_FIELDS.get(body.get("command"))
            if field in body and self.printer_key is None:
                self.cert_ok[via] = False
            await self._ensure_cert(via)
            if field in body and self.printer_key is not None:
                body[field + "_enc"] = encrypt_field(self.printer_key, str(body.pop(field)))
            wire = self.signer.envelope(body)
            self.recent.append({"at": time.time(), "command": _summary(frame), "via": via, "signed": True,
                                "seq": seq, "answer": None})
            log.info("%s: %s via %s (admin, seq %s) %s", self.serial, _summary(frame), via, seq, _args(body))
            self._send(via, wire)
            try:
                return await asyncio.wait_for(fut, timeout)
            except asyncio.TimeoutError:
                return {"result": "FAIL", "reason": "no answer from the printer"}
        finally:
            self._waiters.pop(seq, None)


def _args(body: dict) -> str:
    """Command arguments for the log, without the long or irrelevant fields."""
    return json.dumps({k: v for k, v in body.items() if k not in ("command", "sequence_id")
                       and not (isinstance(v, str) and len(v) > 80)}, separators=(",", ":"))[:300]


def _summary(frame) -> str:
    if not isinstance(frame, dict):
        return repr(frame)[:60]
    return ",".join(f"{k}.{v.get('command')}" for k, v in frame.items() if isinstance(v, dict) and k != "header")
