"""Allowlist-only HTTPS (CONNECT) egress proxy for the Docker sandbox.

Runs in its own container that is attached to both the internal (no-internet) agent network and a normal network.
Only `CONNECT <allowed-host>:443` is honoured; everything else (other hosts, other ports, plain HTTP) is refused.
No wildcards, no IP literals: the allowlist is an explicit list of hostnames chosen by the user.

  python -m mcp_chaos.sandbox.egress_proxy --allow generativelanguage.googleapis.com --port 3128
"""
from __future__ import annotations

import argparse
import asyncio
import re

HOST_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$")


def validate_allowlist(hosts: list[str]) -> list[str]:
    out = []
    for h in hosts:
        h = h.strip().lower()
        if not HOST_RE.match(h):  # rejects '*', IP literals, ports, paths
            raise ValueError(f"egress allowlist entries must be plain hostnames (no wildcards, IPs or ports): {h!r}")
        out.append(h)
    return out


async def _pipe(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
    try:
        while data := await r.read(65536):
            w.write(data)
            await w.drain()
    except (ConnectionError, asyncio.CancelledError):
        pass
    finally:
        try:
            w.close()
        except Exception:
            pass


def make_handler(allow: set[str], log=print):
    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=15)
            first = head.split(b"\r\n", 1)[0].decode("latin-1")
            parts = first.split()
            if len(parts) != 3 or parts[0] != "CONNECT":
                writer.write(b"HTTP/1.1 405 Method Not Allowed\r\n\r\n")
                log(f"refused non-CONNECT: {first[:80]}")
                return
            host, _, port = parts[1].rpartition(":")
            if host.lower() not in allow or port != "443":
                writer.write(b"HTTP/1.1 403 Forbidden\r\n\r\n")
                log(f"refused CONNECT {parts[1]}")
                return
            up_r, up_w = await asyncio.wait_for(asyncio.open_connection(host, 443), timeout=15)
            writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await writer.drain()
            log(f"allowed CONNECT {host}:443")
            await asyncio.gather(_pipe(reader, up_w), _pipe(up_r, writer))
        except Exception as exc:  # malformed request, upstream failure, timeout
            log(f"error: {type(exc).__name__}")
        finally:
            try:
                writer.close()
            except Exception:
                pass

    return handle


async def serve(allow: list[str], port: int, host: str = "0.0.0.0") -> None:
    srv = await asyncio.start_server(make_handler(set(validate_allowlist(allow))), host, port)
    async with srv:
        await srv.serve_forever()


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--allow", action="append", required=True)
    ap.add_argument("--port", type=int, default=3128)
    a = ap.parse_args()
    asyncio.run(serve(a.allow, a.port))
