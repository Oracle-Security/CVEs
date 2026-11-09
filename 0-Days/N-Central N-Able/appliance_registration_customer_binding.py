#!/usr/bin/env python3
import argparse
import html
import json
import xml.etree.ElementTree as ET

import requests
import urllib3


def customer_list(username, password):
    return f'''<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"
 xmlns:e="http://ei2.nobj.nable.com/"><soap:Body><e:customerList>
 <e:username>{html.escape(username)}</e:username><e:password>{html.escape(password)}</e:password>
 <e:settings><e:key>listSOs</e:key><e:value>false</e:value></e:settings>
 </e:customerList></soap:Body></soap:Envelope>'''


def token_for(body, wanted):
    root = ET.fromstring(body)
    for returned in root.findall('.//{*}customerListResponse/{*}return'):
        row = {}
        for item in returned.findall('./{*}items'):
            key = item.findtext('./{*}first') or item.findtext('./{*}key')
            value = item.findtext('./{*}second') or item.findtext('./{*}value') or ""
            if key:
                row[key] = value
        if row.get("customer.customerid") == str(wanted) and row.get("customer.registrationtoken"):
            return row["customer.registrationtoken"]
    raise RuntimeError("registration token not returned")


def registration(token, customer_id, appliance_id):
    customer = '<m:CustomerID xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:nil="true"/>'
    if customer_id is not None:
        customer = f'<m:CustomerID>{customer_id}</m:CustomerID>'
    return f'''<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"
 xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
 xmlns:m="http://mms3.nobj.nable.com/"><soap:Body><m:ApplianceRegistration>
 <m:applianceRegistration><m:ApplianceID>{appliance_id}</m:ApplianceID>{customer}
 <m:IPAddress>127.0.0.1</m:IPAddress><m:ApplianceType>Windows</m:ApplianceType>
 <m:OSID>winnt</m:OSID><m:Version>2026.4.0.31</m:Version>
 <m:ProxyString xsi:nil="true"/><m:AMTCredentials xsi:nil="true"/>
 <m:AutoImport>false</m:AutoImport><m:SilentInstall>false</m:SilentInstall>
 <m:RegistrationToken>{html.escape(token)}</m:RegistrationToken>
 <m:HardwareID>operator-client</m:HardwareID></m:applianceRegistration>
 <m:timeZone>-05:00</m:timeZone></m:ApplianceRegistration></soap:Body></soap:Envelope>'''


def rejected(response):
    text = response.text.lower()
    return response.status_code == 200 and "registration token" in text and (
        "not found" in text or "not applicable" in text or "expired" in text)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("credentials", help="Technician username/password JSON")
    parser.add_argument("--target", default="https://192.168.1.14")
    parser.add_argument("--customer-id", type=int, required=True)
    parser.add_argument("--appliance-id", type=int, default=2147483001)
    args = parser.parse_args()
    credential = json.load(open(args.credentials, encoding="utf-8"))
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    http = requests.Session()
    http.verify = False
    headers = {"Content-Type": "application/soap+xml; charset=UTF-8"}
    origin = args.target.rstrip("/")
    listed = http.post(origin + "/dms2/services2/ServerEI2",
                       data=customer_list(credential["username"], credential["password"]),
                       headers=headers, timeout=30)
    listed.raise_for_status()
    token = token_for(listed.content, args.customer_id)
    endpoint = origin + "/dms2/services2/ServerMMS3"
    valid = http.post(endpoint, data=registration(token, args.customer_id, args.appliance_id),
                      headers=headers, timeout=30)
    invalid = http.post(endpoint, data=registration("00000000-0000-0000-0000-000000000000",
                                                    args.customer_id, args.appliance_id),
                        headers=headers, timeout=30)
    omitted = http.post(endpoint, data=registration(token, None, args.appliance_id),
                        headers=headers, timeout=30)
    passed = valid.status_code == 500 and "no local asset information was sent" in valid.text.lower()
    print(f"valid_supplied_customer_http={valid.status_code} post_auth={passed}")
    print(f"invalid_token_http={invalid.status_code} rejected={rejected(invalid)}")
    print(f"customer_omitted_http={omitted.status_code} rejected={rejected(omitted)}")
    return 0 if passed and rejected(invalid) and rejected(omitted) else 1


if __name__ == "__main__":
    raise SystemExit(main())
