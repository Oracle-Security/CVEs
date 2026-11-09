#!/usr/bin/env python3
import argparse
import re

import requests
import urllib3


def check(target, email):
    session = requests.Session()
    page = session.get(
        target.rstrip("/") + "/requestPasswordResetAction.action",
        verify=False,
        timeout=30,
    )
    page.raise_for_status()
    match = re.search(rb'name=["\']token["\'][^>]*value=["\']([^"\']+)', page.content)
    if not match:
        match = re.search(rb'value=["\']([^"\']+)["\'][^>]*name=["\']token["\']', page.content)
    if not match:
        raise RuntimeError("Struts token not found")

    response = session.post(
        target.rstrip("/") + "/sendPasswordResetAction.action",
        data={"struts.token.name": "token", "token": match.group(1).decode(), "email": email},
        verify=False,
        timeout=30,
    )
    response.raise_for_status()
    accepted = not re.search(rb'<input[^>]+name=["\']email["\']', response.content)
    print(f"email={email} http={response.status_code} bytes={len(response.content)} result={'accepted' if accepted else 'request_form'}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("email", nargs="+")
    parser.add_argument("--target", default="https://192.168.1.14:8443")
    args = parser.parse_args()
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    for email in args.email:
        check(args.target, email)


if __name__ == "__main__":
    main()
