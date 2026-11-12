#!/usr/bin/env python3
import argparse
import xml.etree.ElementTree as ET

import requests
import urllib3


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", default="https://n-central.local")
    parser.add_argument("--appliance-id", type=int, required=True)
    parser.add_argument("--session-id", type=int, default=-1)
    parser.add_argument("--dequeue", action="store_true")
    args = parser.parse_args()
    if not args.dequeue:
        parser.error("--dequeue is required because this operation removes pending actions")

    body = (
        '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" '
        'xmlns:m="http://mms2.nobj.nable.com/"><s:Body><m:MaintActionGet>'
        f'<m:sessionID>{args.session_id}</m:sessionID>'
        f'<m:applianceID>{args.appliance_id}</m:applianceID>'
        '</m:MaintActionGet></s:Body></s:Envelope>'
    )
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    response = requests.post(
        args.target.rstrip("/") + "/dms2/services2/ServerMMS2",
        data=body,
        headers={"Content-Type": "application/soap+xml; charset=UTF-8"},
        verify=False,
        timeout=30,
    )
    response.raise_for_status()
    root = ET.fromstring(response.content)
    actions = [
        node.text for node in root.iter()
        if node.tag.rsplit("}", 1)[-1] == "return" and node.text
    ]
    print("\n".join(actions))


if __name__ == "__main__":
    main()
