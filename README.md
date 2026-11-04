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

## Legal

This tool interoperates with printers **you own**, using an app certificate **you
provide** from software **you installed**. It reproduces Bambu's LAN protocol by
reverse engineering, and it uses the app certificate to sign commands your printer
would otherwise require Developer Mode for. Bambu's terms of service may disallow
unofficial clients. Use it on your own equipment and at your own risk.

## License

TBD — not yet chosen. Do not redistribute until a license is added.
