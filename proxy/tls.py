"""Proxy TLS: a local CA and one server cert covering every virtual IP, made on first start."""

from __future__ import annotations

import datetime as dt
import ipaddress
import logging
import ssl
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

log = logging.getLogger("tls")


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _write_key(path: Path, key) -> None:
    path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                                       serialization.NoEncryption()))


def ensure(folder: Path, ips: list[str]) -> ssl.SSLContext:
    """Return a server context, regenerating the server cert when the IP set changes."""
    folder.mkdir(parents=True, exist_ok=True)
    ca_key_p, ca_p = folder / "ca.key", folder / "ca.pem"
    key_p, cert_p, ips_p = folder / "server.key", folder / "server.pem", folder / "server.ips"
    now = dt.datetime.now(dt.timezone.utc)

    if not ca_p.exists():
        ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        ca = (x509.CertificateBuilder().subject_name(_name("bambu-lan-proxy CA")).issuer_name(_name("bambu-lan-proxy CA"))
              .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
              .not_valid_before(now - dt.timedelta(days=1)).not_valid_after(now + dt.timedelta(days=3650))
              .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
              .sign(ca_key, hashes.SHA256()))
        _write_key(ca_key_p, ca_key)
        ca_p.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
        log.info("made proxy CA %s", ca_p)

    wanted = ",".join(sorted(ips))
    if not cert_p.exists() or not ips_p.exists() or ips_p.read_text() != wanted:
        ca_key = serialization.load_pem_private_key(ca_key_p.read_bytes(), None)
        ca = x509.load_pem_x509_certificate(ca_p.read_bytes())
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        san = [x509.IPAddress(ipaddress.ip_address(ip)) for ip in ips]
        cert = (x509.CertificateBuilder().subject_name(_name("bambu-lan-proxy")).issuer_name(ca.subject)
                .public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - dt.timedelta(days=1)).not_valid_after(now + dt.timedelta(days=825))
                .add_extension(x509.SubjectAlternativeName(san), critical=False)
                .sign(ca_key, hashes.SHA256()))
        _write_key(key_p, key)
        cert_p.write_bytes(cert.public_bytes(serialization.Encoding.PEM) + ca_p.read_bytes())
        ips_p.write_text(wanted)
        log.info("made server cert for %s", wanted)

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert_p, key_p)
    return ctx
