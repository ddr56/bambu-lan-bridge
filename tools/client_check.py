"""Act like a LAN client against the proxy: wrong code refused, pushall answered,
an idle-state pause signed by the proxy (or dropped with --read-only).

    python tools/client_check.py 127.0.0.1 18883 <serial> <code> [--read-only]
"""

from __future__ import annotations

import json
import ssl
import sys
import threading
import time

import paho.mqtt.client as mqtt


def connect(host: str, port: int, code: str):
    c = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=f"check-{time.time_ns() % 100000}")
    c.username_pw_set("bblp", code)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    c.tls_set_context(ctx)
    result = {}
    done = threading.Event()
    c.on_connect = lambda cl, u, f, rc, p: (result.setdefault("rc", rc), done.set())
    c.connect(host, port, keepalive=30)
    c.loop_start()
    done.wait(10)
    return c, result.get("rc")


def main() -> int:
    host, port, serial, code = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]
    signed = "--read-only" not in sys.argv
    ok = True

    c, rc = connect(host, port, "00000000")
    print(f"wrong code      -> {rc}")
    ok &= rc is not None and rc.is_failure
    c.loop_stop()

    c, rc = connect(host, port, code)
    print(f"right code      -> {rc}")
    ok &= rc is not None and not rc.is_failure
    state, msgs = {}, []
    c.on_message = lambda cl, u, m: (msgs.append(m.payload), state.update(json.loads(m.payload).get("print", {})))
    c.subscribe(f"device/{serial}/report")
    time.sleep(1)
    c.publish(f"device/{serial}/request", json.dumps({"pushing": {"sequence_id": "0", "command": "pushall"}}))
    c.publish(f"device/{serial}/request", json.dumps({"print": {"sequence_id": "0", "command": "pushall"}}))
    end = time.time() + 20
    while "gcode_state" not in state and time.time() < end:
        time.sleep(0.2)
    print(f"pushall         -> {len(msgs)} reports, gcode_state={state.get('gcode_state')}, "
          f"ams units={len(state.get('ams', {}).get('ams', []))}")
    ok &= "gcode_state" in state

    if state.get("gcode_state") not in ("IDLE", "FINISH", "FAILED"):
        print("printer busy: skipping the pause check")
        c.loop_stop()
        return 0 if ok else 1
    before = len(msgs)
    c.publish(f"device/{serial}/request", json.dumps({"print": {"sequence_id": "21000", "command": "pause"}}))
    time.sleep(10)
    acks = [json.loads(m).get("print", {}) for m in msgs[before:] if b'"21000"' in m]
    leaked = [m for m in msgs[before:] if b"app_cert_install" in m]
    if signed:
        reason = acks[0].get("reason") if acks else None
        print(f"pause (signed)  -> {reason or 'no answer'}  (want ERROR STATE: signature accepted, nothing to pause)")
        ok &= reason == "ERROR STATE"
        print(f"cert install ack hidden from client -> {not leaked}")
        ok &= not leaked
    else:
        print(f"pause (control) -> {'ANSWERED (should be dropped)' if acks else 'dropped, no answer'}")
        ok &= not acks
    c.loop_stop()
    c.disconnect()
    print("PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
