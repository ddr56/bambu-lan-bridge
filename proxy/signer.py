"""Sign print.* frames with the Bambu Studio app identity (key.pem, chain.pem, crl.pem).

Scheme: BambuPrinterAPI-POC docs/protocol.md. Serialize the print value once,
sign '{"print":<value>}', and send exactly those bytes.
"""

from __future__ import annotations

import base64
import json
import random
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

# Read-only print commands the printer accepts without a signature.
UNSIGNED_PRINT_COMMANDS = frozenset({"pushall", "get_version", "get_access_code"})


class Signer:
    def __init__(self, folder: Path) -> None:
        folder = Path(folder)
        self.key = serialization.load_pem_private_key((folder / "key.pem").read_bytes(), None)
        self.chain = (folder / "chain.pem").read_text()
        crl = folder / "crl.pem"
        self.crl = crl.read_text() if crl.exists() else ""
        leaf = x509.load_pem_x509_certificate(self.chain.split("-----END CERTIFICATE-----")[0].encode()
                                              + b"-----END CERTIFICATE-----\n")
        serial = format(leaf.serial_number, "x")
        if len(serial) % 2:
            serial = "0" + serial
        self.cert_id = serial + leaf.issuer.rfc4514_string()
        self.not_after = leaf.not_valid_after_utc

    def envelope(self, print_obj: dict) -> str:
        print_text = json.dumps(print_obj, separators=(",", ":"), sort_keys=True)
        signed = ('{"print":' + print_text + "}").encode()
        sig = self.key.sign(signed, padding.PKCS1v15(), hashes.SHA256())
        header = {
            "cert_id": self.cert_id,
            "payload_len": len(signed),
            "sign_alg": "RSA_SHA256",
            "sign_string": base64.b64encode(sig).decode(),
            "sign_ver": "v1.0",
        }
        return '{"header":' + json.dumps(header, separators=(",", ":"), sort_keys=True) + ',"print":' + print_text + "}"

    def cert_install(self, sequence_id: str) -> str:
        return json.dumps({"security": {"command": "app_cert_install", "sequence_id": sequence_id,
                                        "app_cert": self.chain, "crl": self.crl}})


def printer_public_key(printer_cert_pem: str):
    """Public key of the printer's device cert (leaf first), as returned by app_cert_install."""
    leaf = printer_cert_pem.split("-----END CERTIFICATE-----")[0] + "-----END CERTIFICATE-----\n"
    return x509.load_pem_x509_certificate(leaf.encode()).public_key()


def encrypt_field(public_key, text: str) -> str:
    """url_enc / param_enc: blockwise RSA PKCS#1 v1.5 under the printer's key, Base64.

    Secured firmware refuses a cleartext url in project_file (84033544) and
    cleartext G-code in gcode_line. Format per open-bambu-networking research §10.3.
    """
    data = text.encode()
    chunk = public_key.key_size // 8 - 11
    out = b"".join(public_key.encrypt(data[i:i + chunk], padding.PKCS1v15())
                   for i in range(0, len(data), chunk))
    return base64.b64encode(out).decode()


# command -> cleartext field that secured firmware wants encrypted instead
ENCRYPTED_FIELDS = {"project_file": "url", "gcode_line": "param"}


class SequenceIds:
    """Decimal-string ids in Studio's 20000-29999 window, monotonic per process."""

    def __init__(self) -> None:
        self._next = random.randint(20000, 22000)

    def take(self) -> str:
        if self._next > 29999:
            self._next = 20000
        self._next += 1
        return str(self._next)


def needs_signature(frame: dict) -> bool:
    body = frame.get("print")
    return isinstance(body, dict) and "header" not in frame and body.get("command") not in UNSIGNED_PRINT_COMMANDS
