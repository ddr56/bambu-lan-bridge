"""Send an idle-state pause through the proxy with different sequence_ids and print the answers.

    python tools/seq_check.py 127.0.0.1 18883 <serial> <code> 0 21000 123456 ...
"""

from __future__ import annotations

import json
import ssl
import sys
import time

import paho.mqtt.client as mqtt


def main() -> int:
    host, port, serial, code, *seqs = sys.argv[1:]
    answers: dict[str, dict] = {}
    c = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=f"seqcheck-{time.time_ns() % 100000}")
    c.username_pw_set("bblp", code)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    c.tls_set_context(ctx)

    def on_message(cl, u, m):
        body = json.loads(m.payload).get("print", {})
        if body.get("command") == "pause":
            answers[str(body.get("sequence_id"))] = body

    c.on_message = on_message
    c.connect(host, int(port), keepalive=30)
    c.loop_start()
    c.subscribe(f"device/{serial}/report")
    time.sleep(1)
    for s in seqs:
        c.publish(f"device/{serial}/request", json.dumps({"print": {"sequence_id": s, "command": "pause"}}))
        time.sleep(3)
    time.sleep(3)
    for s in seqs:
        a = answers.get(s)
        print(f"seq {s:>8}: " + (f"result={a.get('result')} reason={a.get('reason')} err_code={a.get('err_code')}" if a else "no answer"))
    c.loop_stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
