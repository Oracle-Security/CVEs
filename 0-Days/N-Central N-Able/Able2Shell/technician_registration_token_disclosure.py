#!/usr/bin/env python3
import argparse
import html
import json
import xml.etree.ElementTree as ET

import requests
import urllib3


def envelope(username, password):
    return f'''<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"
 xmlns:e="http://ei2.nobj.nable.com/"><soap:Body><e:customerList>
 <e:username>{html.escape(username)}</e:username><e:password>{html.escape(password)}</e:password>
 <e:settings><e:key>listSOs</e:key><e:value>false</e:value></e:settings>
 </e:customerList></soap:Body></soap:Envelope>'''


def customers(body):
    result = []
    root = ET.fromstring(body)
    for returned in root.findall('.//{*}customerListResponse/{*}return'):
        row = {}
        for item in returned.findall('./{*}items'):
            key = item.findtext('./{*}first') or item.findtext('./{*}key')
            value = item.findtext('./{*}second') or item.findtext('./{*}value') or ""
            if key:
                row[key] = value
        result.append(row)
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("credentials", help="JSON file with username and password")
    parser.add_argument("--target", default="https://192.168.1.14")
    parser.add_argument("--show-secrets", action="store_true")
    args = parser.parse_args()
    credential = json.load(open(args.credentials, encoding="utf-8"))
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    response = requests.post(
        args.target.rstrip("/") + "/dms2/services2/ServerEI2",
        data=envelope(credential["username"], credential["password"]),
        headers={"Content-Type": "application/soap+xml; charset=UTF-8"},
        verify=False,
        timeout=30,
    )
    response.raise_for_status()
    count = 0
    for row in customers(response.content):
        token = row.get("customer.registrationtoken", "")
        if not token:
            continue
        count += 1
        if args.show_secrets:
            print(f"customer={row.get('customer.customerid')} token={token} "
                  f"expiry={row.get('customer.registrationtokenexpirydate')}")
        else:
            print(f"customer={row.get('customer.customerid')} token_present=True "
                  f"expiry_present={bool(row.get('customer.registrationtokenexpirydate'))}")
    return 0 if count else 1


if __name__ == "__main__":
    raise SystemExit(main())
