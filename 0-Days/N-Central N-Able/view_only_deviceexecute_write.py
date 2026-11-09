#!/usr/bin/env python3
import argparse
import getpass
import html
import os
import xml.etree.ElementTree as ET

import requests
import urllib3


def post(session, target, path, body):
    response = session.post(
        target.rstrip("/") + path,
        data=body.encode(),
        headers={"Content-Type": "application/soap+xml; charset=UTF-8"},
        verify=False,
        timeout=45,
    )
    response.raise_for_status()
    return response


def text(root, name):
    node = next((x for x in root.iter() if x.tag.rsplit("}", 1)[-1] == name), None)
    return node.text if node is not None else ""


def pairs(raw):
    result = set()
    for node in ET.fromstring(raw).iter():
        if node.tag.rsplit("}", 1)[-1] != "ComplexValues":
            continue
        fields = {x.tag.rsplit("}", 1)[-1]: x.text or "" for x in node}
        result.add((fields.get("Key1", ""), fields.get("Values", "")))
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", default="https://192.168.1.14")
    parser.add_argument("--username", required=True)
    parser.add_argument("--password", default=os.getenv("NCENTRAL_PASSWORD"))
    parser.add_argument("--device-id", type=int, default=506682778)
    parser.add_argument("--appliance-id", type=int, default=1177049630)
    parser.add_argument("--key", required=True)
    parser.add_argument("--value", required=True)
    args = parser.parse_args()
    password = args.password or getpass.getpass("Password: ")

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    session = requests.Session()
    sid = None
    wrote = False
    key, value = html.escape(args.key), html.escape(args.value)
    username, password = html.escape(args.username), html.escape(password)

    hello = f'''<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:m="http://mms2.nobj.nable.com/"><s:Body><m:SessionHello><m:version>2.0.0</m:version><m:applianceVersion>1.0.0.0</m:applianceVersion><m:agent_OSID>winnt</m:agent_OSID><m:agent_OS>Windows</m:agent_OS><m:applianceID>{args.appliance_id}</m:applianceID><m:timeZoneID>-05:00</m:timeZoneID></m:SessionHello></s:Body></s:Envelope>'''
    clear = f'''<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:i="http://ii2.nobj.nable.com/"><s:Body><i:deviceExecuteClear><i:credentials><i:password>{password}</i:password><i:username>{username}</i:username></i:credentials><i:deviceIds>{args.device_id}</i:deviceIds></i:deviceExecuteClear></s:Body></s:Envelope>'''

    try:
        response = post(session, args.target, "/dms2/services2/ServerMMS2", hello)
        sid = text(ET.fromstring(response.content), "return")
        if not sid or not sid.isdigit():
            raise RuntimeError("SessionHello did not return a numeric session")

        read = f'''<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:m="http://mms2.nobj.nable.com/"><s:Body><m:ApplianceGetConfig><m:sessionID>{sid}</m:sessionID><m:configTypes>DeviceExecute</m:configTypes></m:ApplianceGetConfig></s:Body></s:Envelope>'''
        baseline = post(session, args.target, "/dms2/services2/ServerMMS2", read)
        if (args.key, args.value) in pairs(baseline.content):
            raise RuntimeError("requested value already exists")

        write = f'''<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:i="http://ii2.nobj.nable.com/"><s:Body><i:deviceExecute><i:credentials><i:password>{password}</i:password><i:username>{username}</i:username></i:credentials><i:deviceIds>{args.device_id}</i:deviceIds><i:config><i:key>{key}</i:key><i:value>{value}</i:value></i:config></i:deviceExecute></s:Body></s:Envelope>'''
        response = post(session, args.target, "/dms2/services2/ServerII2", write)
        wrote = True
        readback = post(session, args.target, "/dms2/services2/ServerMMS2", read)
        if (args.key, args.value) not in pairs(readback.content):
            raise RuntimeError("appliance readback did not contain the supplied pair")
        print(f"write_http={response.status_code} readback=true")

        response = post(session, args.target, "/dms2/services2/ServerII2", clear)
        wrote = False
        after = post(session, args.target, "/dms2/services2/ServerMMS2", read)
        print(f"clear_http={response.status_code} cleanup_absent={(args.key, args.value) not in pairs(after.content)}")
    finally:
        if wrote:
            try:
                post(session, args.target, "/dms2/services2/ServerII2", clear)
            except Exception:
                pass
        if sid:
            quit_xml = f'''<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:m="http://mms2.nobj.nable.com/"><s:Body><m:SessionQuit><m:sessionID>{sid}</m:sessionID><m:shutdown>false</m:shutdown></m:SessionQuit></s:Body></s:Envelope>'''
            try:
                post(session, args.target, "/dms2/services2/ServerMMS2", quit_xml)
            except Exception:
                pass


if __name__ == "__main__":
    main()
