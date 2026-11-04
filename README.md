# bambu-lan-bridge

A small, LAN-only signing proxy for Bambu Lab printers. It presents each printer
as a virtual LAN-mode device on your own network. Clients (Bambu Studio, OrcaSlicer,
Bambuddy, Home Assistant, a dashboard) connect to that virtual device and send
plain commands; the proxy signs the privileged ones with the Bambu Studio app
certificate **you provide**, so a cloud-bound printer accepts them **without
Developer Mode**.

- **No Bambu account.** It never logs in to Bambu's cloud. Everything is on your LAN.
- **Nothing of Bambu's is shipped.** You supply your own app certificate; the proxy only uses it.
- **Pure Python.** No compiled components, no external signing library.

## How it works

1. Each printer gets a **virtual IP** on your LAN. The proxy runs a small MQTT
   server there and advertises the printer over SSDP so clients discover it.
2. A client connects to the virtual device with the printer's normal **access code**.
3. The proxy connects to the **real printer** over LAN MQTT, installs the app
   certificate into its (RAM-only) trust store, and **signs** every `print.*`
   command the client sends — including print jobs (`url`/`param` encryption).
4. Reports are passed back to the client with the printer presented as
   "developer mode on", so the client sends plain commands the proxy signs.
5. FTPS (file upload), the file service and the RTSPS camera are passed straight
   through to the real printer.

## Quick start

Requires Docker with **host networking** (so the virtual IPs live on your LAN and
other machines can reach them) and `NET_ADMIN` (to add the virtual IPs).

```sh
cp .env.example .env            # set LAN_INTERFACE to your host's LAN NIC (e.g. eth0, ens18)
docker compose up -d
```

Open the admin page at `http://<host>:8099/`. The password is in
`data/admin_password` (or set `ADMIN_PASSWORD`). Then:

1. **Add each printer** — pick it from the discovered list, or enter its serial,
   model, real IP, a free **virtual IP**, and its **access code** (on the printer
   screen under the network/LAN settings).
2. **Upload your certificate** — `key.pem`, `chain.pem` and (optional) `crl.pem`.
   One set covers all your printers. See below for how to get it.
3. **Apply & restart.**
4. **Point your client** at the **virtual IP** instead of the printer's real IP.

## Getting a certificate

This proxy does **not** ship or download any Bambu key. You supply your own
Bambu Studio app key set — `key.pem`, `chain.pem` and (optionally) `crl.pem` —
and upload it on the admin page. One set covers all your printers. How you obtain
your own installation's identity from your own Bambu Studio is up to you and out
of scope for this project.

A self-signed certificate works on some models (e.g. P2S) that don't validate the
chain, and needs nothing from Bambu — but secured firmware (H2C, H2D) rejects it,
so those need your real app certificate.

## Limitations

- **Secured firmware needs the genuine app certificate.** Self-signed is refused there.
- **Host networking is required** for SSDP discovery and the virtual IPs to reach your LAN.
- The camera needs **LAN Only Liveview** enabled on the printer (the proxy relays
  port 322). Turning it on does **not** disable cloud video: the Bambu app
  (Handy) keeps working for remote viewing over the internet, so both the LAN
  stream (to local clients, through the proxy) and cloud liveview work at once.
- The access code is not auto-filled (no cloud) — read it off the printer screen once.

## Status / scope

LAN-only by design. There is deliberately no Bambu cloud login, no cloud print,
and no automatic certificate acquisition.

## Tested printers

So far this has only been verified against a **Bambu Lab H2D** and **H2C** (on
their 2026 secured firmware). Other models are expected to work — the LAN
protocol is the same — but are **untested**, so treat them as unverified:

- **P-series / X-series / A-series (P1S, P1P, X1C, X1E, A1, A1 mini, …)** should
  work with your own app certificate, but nobody has confirmed it yet.
- Some models reportedly accept a **self-signed** certificate (no Bambu key
  needed); others require the genuine app certificate. Which applies varies by
  model and firmware.

If you get it working — or not — on a model not listed here, a short issue or PR
noting the model and firmware is very welcome.

## Reporting a problem

If it doesn't work with your printer (say a P1S that won't take commands), please
open an issue with enough detail to reproduce it.

**First, collect debug info:**

1. On the admin page, open **Logs** and click **Enable debug logging** (it logs
   the raw MQTT frames both ways and auto-reverts after 20 minutes).
2. Reproduce the problem from your client.
3. Click **Download diagnostics** — a JSON snapshot of versions, each printer's
   state, recent commands and the log tail. **Access codes are redacted**, but
   skim it before posting anyway.

**Please include in the issue:**

- **Printer model and firmware version** (e.g. P1S, firmware `01.08.xx`).
- **Which client** and version (Bambu Studio, OrcaSlicer, Bambuddy, Home
  Assistant, …), and **what you did** — the action you expected to work.
- **What happened** vs. what you expected, and any error shown in the client.
- Whether the printer is **reachable on the LAN** (can the host `ping` its
  `lan_ip`?) and whether the **access code** is correct.
- From the logs / diagnostics:
  - Did **`app_cert_install via lan`** report **SUCCESS**?
  - The line for your command — is it **signed**, and what did the printer
    **answer** (`result` / `err_code`)?
  - Any Bambu error code, which narrows it down a lot:

    | Code | Meaning |
    |------|---------|
    | `84033543` | no/invalid signature, or the app certificate isn't trusted yet |
    | `84033545` | the printer doesn't trust the app certificate (`app_cert_install` failed, or the printer rebooted since) |
    | `84033547` | certificate not acceptable — not a genuine Bambu chain (a self-signed cert lands here on secured firmware) |
    | `84033548` | the signature doesn't verify — the key doesn't match the certificate |

- Attach the **diagnostics JSON**, or at least the relevant debug log lines.

The single most useful thing is the debug log of one failing command together
with the printer's answer.

## Legal

This tool interoperates with printers **you own**, using an app certificate **you
provide** from software **you installed**. It reproduces Bambu's LAN protocol by
reverse engineering, and it uses the app certificate to sign commands your printer
would otherwise require Developer Mode for. Bambu's terms of service may disallow
unofficial clients. Use it on your own equipment and at your own risk.

## License

[GNU AGPL-3.0](LICENSE).
