"""Aminium Studio - real connection engine (no Kivy imports, so it can be tested anywhere).

What it does
  * parses the vless:// and trojan:// links the panel produces (WebSocket transport, TLS or plain)
  * pings a config three ways: TCP connect, WebSocket handshake, or a REAL delay through the tunnel
  * runs a local proxy (SOCKS5 + HTTP on one port) that sends every connection through the chosen config

The panel's links are exactly what is supported here: type=ws, security=tls|none, vless or trojan.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import ipaddress
import json
import os
import socket
import ssl
import struct
import threading
import time
import uuid as uuidlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

PROXY_PORT = 10808
PING_MODES = ("Real delay", "Handshake", "TCP")
_UA = "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Mobile Safari/537.36"


# ───────────────────────────── links ─────────────────────────────
def parse_link(link: str) -> dict | None:
    """vless:// or trojan:// (ws transport) -> config dict, or None if unsupported."""
    link = (link or "").strip()
    if not link.startswith(("vless://", "trojan://")):
        return None
    try:
        u = urlparse(link)
        q = {k: v[0] for k, v in parse_qs(u.query, keep_blank_values=True).items()}
        secret = unquote(u.username or "")
        addr = u.hostname
        port = u.port or 443
        if not secret or not addr:
            return None
        if q.get("type", "tcp") != "ws":
            return None
        sec = q.get("security", "none")
        if sec not in ("tls", "none"):
            return None
        host = q.get("host") or q.get("sni") or addr
        cfg = {
            "proto": u.scheme, "secret": secret, "addr": addr, "port": int(port),
            "tls": sec == "tls", "sni": q.get("sni") or host, "host": host,
            "path": q.get("path") or "/", "name": unquote(u.fragment) or f"{addr}:{port}",
        }
        if u.scheme == "vless":
            uuidlib.UUID(secret)                       # validates the id
        return cfg
    except Exception:
        return None


def make_item(link: str) -> dict | None:
    cfg = parse_link(link)
    if not cfg:
        return None
    return {"link": link.strip(), "name": cfg["name"], "proto": cfg["proto"], "addr": cfg["addr"],
            "port": cfg["port"], "ping": None, "mode": ""}


def merge_links(items: list, links: list) -> tuple[list, int, int]:
    """add new links to the saved list. returns (items, added, unsupported)"""
    have = {it["link"] for it in items}
    added = bad = 0
    for l in links:
        l = (l or "").strip()
        if not l or l in have:
            continue
        it = make_item(l)
        if it is None:
            if l.startswith(("vless://", "trojan://", "vmess://", "ss://")):
                bad += 1
            continue
        items.append(it)
        have.add(l)
        added += 1
    return items, added, bad


def load_items(path: Path) -> list:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return [x for x in data.get("items", []) if isinstance(x, dict) and x.get("link")]
    except Exception:
        return []


def save_items(path: Path, items: list, selected: str = "") -> None:
    try:
        Path(path).write_text(json.dumps({"items": items, "selected": selected}, ensure_ascii=False), encoding="utf-8")
    except Exception:
        pass


def load_selected(path: Path) -> str:
    try:
        return json.loads(Path(path).read_text(encoding="utf-8")).get("selected", "")
    except Exception:
        return ""


# ───────────────────────────── websocket + tunnel ─────────────────────────────
def _ssl_ctx() -> ssl.SSLContext:
    try:
        import certifi  # type: ignore
        ctx = ssl.create_default_context(cafile=certifi.where())
    except Exception:
        ctx = ssl.create_default_context()
    try:
        ctx.set_alpn_protocols(["http/1.1"])           # a WebSocket upgrade needs HTTP/1.1, not h2
    except Exception:
        pass
    return ctx


def _xor(data: bytes, mask: bytes) -> bytes:
    n = len(data)
    if not n:
        return data
    m = (mask * (n // 4 + 1))[:n]
    return (int.from_bytes(data, "big") ^ int.from_bytes(m, "big")).to_bytes(n, "big")


class WsConn:
    def __init__(self, reader, writer):
        self.r, self.w = reader, writer

    async def _frame(self, opcode: int, data: bytes):
        n = len(data)
        mask = os.urandom(4)
        h = bytearray([0x80 | opcode])
        if n < 126:
            h.append(0x80 | n)
        elif n < 65536:
            h.append(0x80 | 126)
            h += struct.pack(">H", n)
        else:
            h.append(0x80 | 127)
            h += struct.pack(">Q", n)
        self.w.write(bytes(h) + mask + _xor(data, mask))
        await self.w.drain()

    async def send(self, data: bytes):
        for i in range(0, len(data), 60000):
            await self._frame(0x2, data[i:i + 60000])

    async def recv(self) -> bytes | None:
        try:
            while True:
                b1, b2 = await self.r.readexactly(2)
                op, masked, n = b1 & 0x0F, b2 & 0x80, b2 & 0x7F
                if n == 126:
                    n = struct.unpack(">H", await self.r.readexactly(2))[0]
                elif n == 127:
                    n = struct.unpack(">Q", await self.r.readexactly(8))[0]
                mk = await self.r.readexactly(4) if masked else None
                payload = await self.r.readexactly(n) if n else b""
                if mk:
                    payload = _xor(payload, mk)
                if op == 0x8:
                    return None
                if op == 0x9:
                    await self._frame(0xA, payload)
                    continue
                if op == 0xA:
                    continue
                return payload
        except (asyncio.IncompleteReadError, ConnectionError, OSError, ssl.SSLError):
            return None

    def close(self):
        try:
            self.w.close()
        except Exception:
            pass


async def ws_connect(cfg: dict, timeout: float = 8.0) -> WsConn:
    ssl_ctx = _ssl_ctx() if cfg["tls"] else None
    r, w = await asyncio.wait_for(
        asyncio.open_connection(cfg["addr"], cfg["port"], ssl=ssl_ctx,
                                server_hostname=(cfg["sni"] if cfg["tls"] else None)), timeout)
    key = base64.b64encode(os.urandom(16)).decode()
    req = (f"GET {cfg['path']} HTTP/1.1\r\nHost: {cfg['host']}\r\nUser-Agent: {_UA}\r\n"
           f"Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\n"
           f"Sec-WebSocket-Version: 13\r\n\r\n")
    w.write(req.encode())
    await w.drain()
    try:
        head = await asyncio.wait_for(r.readuntil(b"\r\n\r\n"), timeout)
    except Exception:
        w.close()
        raise
    status = head.split(b"\r\n", 1)[0]
    if b" 101" not in status:
        w.close()
        raise ConnectionError("server answered: " + status.decode("latin1", "replace")[:60])
    return WsConn(r, w)


def _addr_bytes(host: str, proto: str) -> bytes:
    try:
        ip = ipaddress.ip_address(host)
        if ip.version == 4:
            return b"\x01" + ip.packed
        return (b"\x03" if proto == "vless" else b"\x04") + ip.packed
    except ValueError:
        try:
            b = host.encode("idna")
        except UnicodeError:
            b = host.encode("utf-8")
        return (b"\x02" if proto == "vless" else b"\x03") + bytes([len(b)]) + b


class Tunnel:
    def __init__(self, ws: WsConn, proto: str):
        self.ws, self.proto = ws, proto
        self._strip = proto == "vless"
        self._buf = b""

    async def send(self, data: bytes):
        await self.ws.send(data)

    async def recv(self) -> bytes | None:
        while True:
            d = await self.ws.recv()
            if d is None:
                return None
            if self._strip:                              # vless answers with: version, addon length, addon
                self._buf += d
                if len(self._buf) < 2:
                    continue
                n = 2 + self._buf[1]
                if len(self._buf) < n:
                    continue
                d, self._buf, self._strip = self._buf[n:], b"", False
                if not d:
                    continue
            return d

    def close(self):
        self.ws.close()


async def open_tunnel(cfg: dict, host: str, port: int, timeout: float = 10.0) -> Tunnel:
    ws = await ws_connect(cfg, timeout)
    if cfg["proto"] == "vless":
        hdr = b"\x00" + uuidlib.UUID(cfg["secret"]).bytes + b"\x00\x01" + struct.pack(">H", port) + _addr_bytes(host, "vless")
    else:
        hdr = (hashlib.sha224(cfg["secret"].encode()).hexdigest().encode() + b"\r\n\x01"
               + _addr_bytes(host, "trojan") + struct.pack(">H", port) + b"\r\n")
    try:
        await ws.send(hdr)
    except Exception:
        ws.close()
        raise
    return Tunnel(ws, cfg["proto"])


# ───────────────────────────── ping ─────────────────────────────
async def _ping_tcp(cfg, timeout):
    t0 = time.perf_counter()
    r, w = await asyncio.wait_for(asyncio.open_connection(cfg["addr"], cfg["port"]), timeout)
    ms = int((time.perf_counter() - t0) * 1000)
    w.close()
    return ms


async def _ping_ws(cfg, timeout):
    t0 = time.perf_counter()
    ws = await ws_connect(cfg, timeout)
    ms = int((time.perf_counter() - t0) * 1000)
    ws.close()
    return ms


async def _ping_real(cfg, timeout, target=("cp.cloudflare.com", 80)):
    """the real thing: a tiny HTTP request that travels through the tunnel and back"""
    t0 = time.perf_counter()
    tun = await open_tunnel(cfg, target[0], target[1], timeout)
    try:
        await tun.send(f"GET /generate_204 HTTP/1.1\r\nHost: {target[0]}\r\nUser-Agent: {_UA}\r\nConnection: close\r\n\r\n".encode())
        data = b""
        while b"\r\n" not in data and len(data) < 4096:
            d = await asyncio.wait_for(tun.recv(), timeout)
            if d is None:
                break
            data += d
        if not data.startswith(b"HTTP/"):
            raise ConnectionError("no HTTP answer through the tunnel")
        return int((time.perf_counter() - t0) * 1000)
    finally:
        tun.close()


def ping(cfg: dict, mode: str = "Real delay", timeout: float = 8.0, target=None) -> int:
    """milliseconds, or -1 when it fails"""
    try:
        if mode == "TCP":
            coro = _ping_tcp(cfg, timeout)
        elif mode == "Handshake":
            coro = _ping_ws(cfg, timeout)
        else:
            coro = _ping_real(cfg, timeout, target or ("cp.cloudflare.com", 80))
        return asyncio.run(asyncio.wait_for(coro, timeout + 4))
    except Exception:
        return -1


def ping_many(items: list, mode: str, on_result, workers: int = 6, timeout: float = 8.0, should_stop=lambda: False):
    """ping saved items in parallel; on_result(index, ms) is called for each one"""
    def one(i):
        if should_stop():
            return i, None
        cfg = parse_link(items[i]["link"])
        return i, (ping(cfg, mode, timeout) if cfg else -1)
    with ThreadPoolExecutor(max_workers=workers) as ex:
        for fu in as_completed([ex.submit(one, i) for i in range(len(items))]):
            try:
                i, ms = fu.result()
            except Exception:
                continue
            if ms is not None:
                on_result(i, ms)


# ───────────────────────────── local proxy ─────────────────────────────
async def _relay(cr, cw, tun: Tunnel, stats: dict):
    async def up():
        try:
            while True:
                d = await cr.read(16384)
                if not d:
                    break
                await tun.send(d)
                stats["up"] += len(d)
        except Exception:
            pass

    async def down():
        try:
            while True:
                d = await tun.recv()
                if d is None:
                    break
                cw.write(d)
                await cw.drain()
                stats["down"] += len(d)
        except Exception:
            pass

    t_up, t_down = asyncio.ensure_future(up()), asyncio.ensure_future(down())
    try:
        done, _ = await asyncio.wait({t_up, t_down}, return_when=asyncio.FIRST_COMPLETED)
        if t_up in done and t_down not in done:         # the app finished sending, let the answer arrive
            await asyncio.wait({t_down}, timeout=15)
    finally:
        for t in (t_up, t_down):
            t.cancel()
        tun.close()
        try:
            cw.close()
        except Exception:
            pass


class LocalProxy:
    def __init__(self):
        self.cfg: dict | None = None
        self.port = PROXY_PORT
        self.loop = None
        self.thread = None
        self.server = None
        self.state = "stopped"          # stopped | running | error
        self.error = ""
        self.stats = {"up": 0, "down": 0, "conns": 0, "active": 0, "failed": 0}

    # --- lifecycle ---
    def start(self, cfg: dict, port: int = PROXY_PORT) -> bool:
        self.stop()
        self.cfg, self.port, self.error = cfg, port, ""
        self.stats = {"up": 0, "down": 0, "conns": 0, "active": 0, "failed": 0}
        ready = threading.Event()

        def run():
            loop = asyncio.new_event_loop()
            self.loop = loop
            asyncio.set_event_loop(loop)
            try:
                self.server = loop.run_until_complete(asyncio.start_server(self._handle, "127.0.0.1", port))
                self.state = "running"
            except Exception as e:
                self.error, self.state = str(e), "error"
                ready.set()
                loop.close()
                return
            ready.set()
            try:
                loop.run_forever()
            finally:
                try:
                    self.server.close()
                    tasks = [t for t in asyncio.all_tasks(loop) if not t.done()]
                    for t in tasks:
                        t.cancel()
                    if tasks:
                        loop.run_until_complete(asyncio.gather(*tasks, return_exceptions=True))
                except Exception:
                    pass
                loop.close()
                self.state = "stopped"

        self.thread = threading.Thread(target=run, daemon=True)
        self.thread.start()
        ready.wait(5)
        return self.state == "running"

    def stop(self):
        if self.loop is not None and self.thread is not None and self.thread.is_alive():
            self.loop.call_soon_threadsafe(self.loop.stop)
            self.thread.join(4)
        self.loop = self.thread = self.server = None
        self.state = "stopped"

    # --- connections ---
    async def _handle(self, reader, writer):
        self.stats["conns"] += 1
        self.stats["active"] += 1
        try:
            first = await asyncio.wait_for(reader.readexactly(1), 15)
            if first == b"\x05":
                await self._socks(reader, writer)
            else:
                await self._http(first, reader, writer)
        except asyncio.CancelledError:
            raise
        except Exception:
            self.stats["failed"] += 1
        finally:
            self.stats["active"] -= 1
            try:
                writer.close()
            except Exception:
                pass

    async def _socks(self, r, w):
        n = (await r.readexactly(1))[0]
        await r.readexactly(n)
        w.write(b"\x05\x00")
        ver, cmd, _rsv, atyp = await r.readexactly(4)
        if atyp == 1:
            host = socket.inet_ntoa(await r.readexactly(4))
        elif atyp == 3:
            host = (await r.readexactly((await r.readexactly(1))[0])).decode("utf-8", "replace")
        elif atyp == 4:
            host = socket.inet_ntop(socket.AF_INET6, await r.readexactly(16))
        else:
            return
        port = struct.unpack(">H", await r.readexactly(2))[0]
        if cmd != 1:                                     # only TCP CONNECT
            w.write(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
            return
        try:
            tun = await open_tunnel(self.cfg, host, port)
        except Exception:
            self.stats["failed"] += 1
            w.write(b"\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00")
            return
        w.write(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
        await _relay(r, w, tun, self.stats)

    async def _http(self, first, r, w):
        line = first + await asyncio.wait_for(r.readline(), 15)
        heads = []
        while True:
            h = await asyncio.wait_for(r.readline(), 15)
            if h in (b"\r\n", b"\n", b""):
                break
            heads.append(h)
        parts = line.decode("latin1").split()
        if len(parts) < 3:
            return
        method, target, version = parts[0], parts[1], parts[2]
        if method.upper() == "CONNECT":
            host, _, p = target.rpartition(":")
            host = host.strip("[]")
            try:
                tun = await open_tunnel(self.cfg, host, int(p or 443))
            except Exception:
                self.stats["failed"] += 1
                w.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                return
            w.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await _relay(r, w, tun, self.stats)
            return
        u = urlparse(target)                             # plain http proxy request: GET http://host/path
        if not u.hostname:
            return
        try:
            tun = await open_tunnel(self.cfg, u.hostname, u.port or 80)
        except Exception:
            self.stats["failed"] += 1
            w.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            return
        path = (u.path or "/") + (("?" + u.query) if u.query else "")
        keep = [h for h in heads if not h.lower().startswith((b"proxy-connection", b"connection", b"proxy-authorization"))]
        req = f"{method} {path} {version}\r\n".encode() + b"".join(keep) + b"Connection: close\r\n\r\n"
        await tun.send(req)
        await _relay(r, w, tun, self.stats)


def fmt_bytes(n: int) -> str:
    n = float(n)
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} GB"
