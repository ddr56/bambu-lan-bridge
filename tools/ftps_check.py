"""Implicit FTPS (port 990) check against a printer or the proxy.

    python tools/ftps_check.py <host> <code> pasv      # show a few passive-mode answers
    python tools/ftps_check.py <host> <code> roundtrip # upload, list, download, delete a small test file

Data connections go to the control host (Python's default), which is what a
proxy client does, so this also checks the passive ports are relayed.
"""

from __future__ import annotations

import ftplib
import io
import socket
import ssl
import sys
import time

TEST_NAME = "bambu-lan-proxy-test.txt"


class ImplicitFTPS(ftplib.FTP_TLS):
    def connect(self, host="", port=990, timeout=15, source_address=None):
        self.host, self.port, self.timeout = host, port, timeout
        raw = socket.create_connection((host, port), timeout)
        self.sock = self.context.wrap_socket(raw, server_hostname=host)
        self.af = self.sock.family
        self.file = self.sock.makefile("r", encoding=self.encoding)
        self.welcome = self.getresp()
        return self.welcome

    def ntransfercmd(self, cmd, rest=None):
        conn, size = ftplib.FTP.ntransfercmd(self, cmd, rest)
        # Reuse the control channel's TLS session, which vsftpd-style servers require.
        conn = self.context.wrap_socket(conn, server_hostname=self.host, session=self.sock.session)
        return conn, size


def connect(host: str, code: str) -> ImplicitFTPS:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ftp = ImplicitFTPS(context=ctx)
    ftp.connect(host)
    ftp.login("bblp", code)
    ftp.prot_p()
    return ftp


def main() -> int:
    host, code, action = sys.argv[1:4]
    ftp = connect(host, code)
    print("welcome:", ftp.welcome)
    if action == "pasv":
        for _ in range(4):
            print("PASV ->", ftp.sendcmd("PASV"))
        try:
            print("EPSV ->", ftp.sendcmd("EPSV"))
        except ftplib.error_perm as e:
            print("EPSV ->", e)
    else:
        body = f"bambu-lan-proxy FTPS check {time.ctime()}\n".encode()
        ftp.storbinary(f"STOR {TEST_NAME}", io.BytesIO(body))
        names = ftp.nlst()
        print(f"uploaded {len(body)} bytes; listed: {TEST_NAME in names} ({len(names)} entries)")
        got = io.BytesIO()
        ftp.retrbinary(f"RETR {TEST_NAME}", got.write)
        print("download matches:", got.getvalue() == body)
        ftp.delete(TEST_NAME)
        print("deleted; still listed:", TEST_NAME in ftp.nlst())
    ftp.quit()
    return 0


if __name__ == "__main__":
    sys.exit(main())
