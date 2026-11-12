#!/usr/bin/env python3
import argparse
import html
import json
import xml.etree.ElementTree as ET

import requests
import urllib3


def envelope(caller, account):
    settings = [
        ("email", account["username"]),
        ("password", account["password"]),
        ("customerid", account["customerId"]),
        ("status", "enabled"),
        ("firstname", account.get("firstName", "Operator")),
        ("lastname", account.get("lastName", "Account")),
        ("username", account["username"]),
        ("userroleID", account["roleId"]),
    ]
    settings += [("accessgroupID", value) for value in account.get("accessGroupIds", [])]
    items = "".join(f'<e:settings><e:key>{html.escape(str(key))}</e:key>'
                    f'<e:value>{html.escape(str(value))}</e:value></e:settings>'
                    for key, value in settings)
    return f'''<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"
 xmlns:e="http://ei2.nobj.nable.com/"><soap:Body><e:userAdd>
 <e:username>{html.escape(str(caller["username"]))}</e:username>
 <e:password>{html.escape(str(caller["password"]))}</e:password>
 {items}</e:userAdd></soap:Body></soap:Envelope>'''


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("caller", help="JSON file with low-role username/password")
    parser.add_argument("account", help="JSON file describing the peer account")
    parser.add_argument("--api", default="https://192.168.1.14")
    parser.add_argument("--ui", default="https://192.168.1.14:8443")
    parser.add_argument("--verify-login", action="store_true")
    args = parser.parse_args()
    caller = json.load(open(args.caller, encoding="utf-8"))
    account = json.load(open(args.account, encoding="utf-8"))
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    http = requests.Session()
    http.verify = False
    response = http.post(
        args.api.rstrip("/") + "/dms2/services2/ServerEI2",
        data=envelope(caller, account),
        headers={"Content-Type": "application/soap+xml; charset=UTF-8"},
        timeout=45,
    )
    response.raise_for_status()
    user_id = ET.fromstring(response.content).findtext('.//{*}userAddResponse/{*}return')
    if not user_id or not user_id.isdigit():
        raise RuntimeError("userAdd returned no user ID")
    print(f"created_user_id={user_id}")
    if args.verify_login:
        login = http.post(
            args.ui.rstrip("/") + "/loginLoginAction.action",
            data={"username": account["username"], "password": account["password"],
                  "customerId": account["customerId"], "soName": account.get("soName", "")},
            allow_redirects=False,
            timeout=45,
        )
        location = login.headers.get("Location", "")
        print(f"login_http={login.status_code} location={location}")
        return 0 if login.status_code == 302 and location.endswith("/IndexAction.action") else 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
