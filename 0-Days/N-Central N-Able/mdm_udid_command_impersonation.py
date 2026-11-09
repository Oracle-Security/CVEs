#!/usr/bin/env python3
import argparse
import plistlib

import requests
import urllib3


def put(session, target, body):
    response = session.put(
        target.rstrip("/") + "/mdm/connect",
        data=plistlib.dumps(body),
        headers={"Content-Type": "application/xml"},
        timeout=30,
    )
    response.raise_for_status()
    return response, plistlib.loads(response.content) if response.content else {}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("udid")
    parser.add_argument("--target", default="https://192.168.1.14")
    parser.add_argument("--acknowledge", action="store_true")
    parser.add_argument("--insecure", action="store_true")
    args = parser.parse_args()

    session = requests.Session()
    session.trust_env = True
    session.verify = not args.insecure
    if args.insecure:
        urllib3.disable_warnings()

    response, result = put(session, args.target, {"UDID": args.udid, "Status": "Idle"})
    command = result.get("Command", {})
    command_uuid = result.get("CommandUUID")
    print(f"http={response.status_code}")
    print(f"command={command.get('RequestType')}")
    print(f"command_uuid={command_uuid}")

    if args.acknowledge and command_uuid:
        response, _ = put(
            session,
            args.target,
            {"UDID": args.udid, "Status": "Acknowledged", "CommandUUID": command_uuid},
        )
        print(f"ack_http={response.status_code}")


if __name__ == "__main__":
    main()
