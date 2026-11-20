#!/usr/bin/env python3
"""
Aminium Studio - step-by-step wizard (Aminium Deployer + Cloudflare Clean-IP Scanner in one app)

  Step 1  Token     paste the Cloudflare API token ONCE (kept on this PC; "Change token" lives here)
  Step 2  Clean IPs real scan: TCP + TLS(SNI) + HTTP /cdn-cgi/trace, several rounds, jitter / loss
                    IP version is selectable: IPv4 / IPv4 + IPv6 / IPv6 (fresh random addresses on every launch & scan)
  Step 3  Build     random name / password / panel path / WS path / secret / UUID are generated on every
                    launch -> deploy the Worker (or Pages) -> the found IPs are re-checked against YOUR new
                    worker with a real WebSocket upgrade -> the best ones are written into the panel,
                    so every generated config uses them
  Step 4  Configs   subscription links (v2ray / Clash / sing-box / Xray / Patt), every single config link,
                    QR codes, and "Save all files"

Android (Kivy) edition - same engine, same 4-step wizard, touch-friendly look.
Build the APK with buildozer (see README.md / the GitHub Actions workflow).
Desktop test:  pip install kivy requests qrcode certifi   then   python main.py
Put aminium-pages.zip next to this file (it is bundled into the APK) or pick it in step 3.
"""
from __future__ import annotations

import base64
import collections
import dataclasses
import email
import gzip
import hashlib
import http.client
import ipaddress
import json
import math
import mimetypes
import os
import queue
import random
import re
import secrets
import socket
import ssl
import statistics
import string
import sys
import threading
import time
import types
import zlib
import uuid as uuidlib
import webbrowser
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.parse import quote, unquote, urlparse

import requests

try:
    import qrcode  # type: ignore
except Exception:  # pragma: no cover
    qrcode = None

try:
    import blake3  # type: ignore
except Exception:  # pragma: no cover
    blake3 = None

APP_NAME = "Aminium Studio"
API = "https://api.cloudflare.com/client/v4"
BUNDLE_DIR = Path(__file__).resolve().parent      # main.py + aminium-pages.zip live here (inside the APK on Android)


def _data_dirs():
    """(private data folder, folder for 'Save all files'). Desktop: next to this file.
    Android: the app's private storage (token / settings) + the app's external files folder (saved configs + QR)."""
    if "ANDROID_ARGUMENT" in os.environ:
        try:
            from jnius import autoclass  # type: ignore
            act = autoclass("org.kivy.android.PythonActivity").mActivity
            priv = Path(str(act.getFilesDir().getAbsolutePath()))
            ext = act.getExternalFilesDir(None)
            out = Path(str(ext.getAbsolutePath())) if ext is not None else priv
            return priv, out / "aminium_output"
        except Exception:
            pass
        home = Path(os.environ.get("ANDROID_PRIVATE") or os.environ.get("HOME") or str(BUNDLE_DIR))
        return home, home / "aminium_output"
    return BUNDLE_DIR, BUNDLE_DIR / "aminium_output"


APP_DIR, OUT_DIR = _data_dirs()
CFG_FILE = APP_DIR / "aminium_studio_config.json"
RESULT_FILE = APP_DIR / "aminium_deploy_result.txt"

TOKEN_TEMPLATE = [
    {"key": "page", "type": "edit"},
    {"key": "workers_kv_storage", "type": "edit"},
    {"key": "d1", "type": "edit"},
    {"key": "workers_scripts", "type": "edit"},
    {"key": "account_settings", "type": "read"},
    {"key": "account_analytics", "type": "read"},
]
TOKEN_URL = "https://dash.cloudflare.com/profile/api-tokens"


def token_template_url() -> str:
    keys = quote(json.dumps(TOKEN_TEMPLATE, separators=(",", ":")))
    return f"{TOKEN_URL}?permissionGroupKeys={keys}&name=Aminium%20Studio&accountId=*&zoneId=all"


# ════════════════════════════════════════════════════════════════════════════
#  PART 1 - scanner core (taken unchanged from cf_scanner.py)
# ════════════════════════════════════════════════════════════════════════════

# Official Cloudflare IPv4 ranges (https://www.cloudflare.com/ips-v4)
CF_RANGES = [
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
]
# Official Cloudflare IPv6 ranges (https://www.cloudflare.com/ips-v6)
CF_RANGES_V6 = [
    "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32",
    "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
]
CF_V6_PROBES = ["2606:4700:4700::1111", "2606:4700:4700::1001"]   # 1.1.1.1 over IPv6 (connectivity check)
TLS_PORTS = [443, 2053, 2083, 2087, 2096, 8443]       # Cloudflare HTTPS ports
PLAIN_PORTS = [80, 8080, 8880, 2052, 2082, 2086, 2095]  # Cloudflare HTTP ports
SPEED_HOST = "speed.cloudflare.com"
UA = "Mozilla/5.0 (compatible; CF-Clean-IP-Scanner/1.1)"

# ───────────────────────────── configuration ─────────────────────────────
def new_rng() -> random.Random:
    """A freshly seeded generator from the OS entropy pool: new random addresses on every launch and every scan."""
    return random.Random(secrets.randbits(128))


def _num(v, lo, hi, default, cast=int):
    try:
        x = cast(v)
    except (TypeError, ValueError):
        return default
    return max(lo, min(hi, x))


def _host(v, default):
    v = str(v or "").strip().lower()
    v = re.sub(r"^[a-z]+://", "", v).split("/")[0].split(":")[0]
    return v if re.fullmatch(r"[a-z0-9]([a-z0-9.-]*[a-z0-9])?", v or "") else default


@dataclasses.dataclass
class Config:
    host: str = SPEED_HOST          # SNI + Host header (put your worker domain here for a realistic test)
    port: int = 443
    count: int = 600                # how many IPs to try (neighbours may add up to +50 %)
    threads: int = 32               # too many parallel handshakes choke slow links and everything times out
    timeout: float = 5.0
    rounds: int = 3                 # real test rounds per IP
    target: int = 40                # stop early after this many clean IPs (0 = scan everything)
    mode: str = "spread"            # spread = one IP per /24 block, random = fully random
    custom: str = ""                # extra IPs / CIDR ranges; empty = all Cloudflare ranges
    verify: bool = True             # verify the TLS certificate
    neighbors: bool = True          # probe neighbours of every good IP
    ws: bool = False                # real WebSocket upgrade test
    ws_path: str = "/"
    speed: bool = False             # real download test for the best IPs
    speed_top: int = 10
    speed_bytes: int = 2_000_000
    auto: bool = True               # check the connection first and fix SNI / certificate settings automatically
    force_tls: bool | None = None   # tests only; normally TLS is decided by the port
    family: str = "v4"              # which addresses to generate: v4 | both | v6 (IPv6 is optional)
    fragment: bool = False          # cut the TLS ClientHello into small TCP pieces (same idea as Xray's "fragment")

    @property
    def tls(self) -> bool:
        return self.port not in PLAIN_PORTS if self.force_tls is None else self.force_tls

    @staticmethod
    def from_dict(d: dict) -> "Config":
        d = d or {}
        c = Config()
        c.host = _host(d.get("host"), SPEED_HOST)
        c.port = _num(d.get("port"), 1, 65535, 443)
        c.count = _num(d.get("count"), 1, 5000, 600)
        c.threads = _num(d.get("threads"), 1, 256, 32)
        c.timeout = _num(d.get("timeout"), 0.5, 15, 5.0, float)
        c.rounds = _num(d.get("rounds"), 1, 8, 3)
        c.target = _num(d.get("target"), 0, 2000, 40)
        c.mode = "random" if d.get("mode") == "random" else "spread"
        c.custom = str(d.get("custom") or "")[:20000]
        c.verify = bool(d.get("verify", True))
        c.neighbors = bool(d.get("neighbors", True))
        c.auto = bool(d.get("auto", True))
        c.ws = bool(d.get("ws", False))
        p = str(d.get("ws_path") or "/").strip()
        c.ws_path = p if p.startswith("/") and re.fullmatch(r"[\w\-./%?=&~:@!$+,;]*", p) else "/"
        c.fragment = bool(d.get("fragment", False))
        c.family = d.get("family") if d.get("family") in ("v4", "both", "v6") else "v4"
        c.speed = bool(d.get("speed", False))
        c.speed_top = _num(d.get("speed_top"), 1, 50, 10)
        c.speed_bytes = _num(d.get("speed_bytes"), 100_000, 25_000_000, 2_000_000)
        return c


# ───────────────────────────── real probing ─────────────────────────────
class ProbeError(Exception):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _classify(e: BaseException) -> str:
    msg = str(e).lower()
    if isinstance(e, (socket.timeout, TimeoutError)) or "timed out" in msg:
        return "timeout"
    if isinstance(e, ssl.SSLCertVerificationError):
        return "cert"
    if isinstance(e, ssl.SSLError):
        return "tls"
    if isinstance(e, ConnectionRefusedError):
        return "refused"
    if isinstance(e, (ConnectionResetError, ConnectionAbortedError, BrokenPipeError)):
        return "reset"
    if isinstance(e, OSError):
        return "unreachable"
    return "error"


_CTX: dict = {}


def _ssl_ctx(verify: bool) -> ssl.SSLContext:
    c = _CTX.get(verify)
    if c is None:
        c = ssl.create_default_context()
        try:
            import certifi  # optional
            c.load_verify_locations(certifi.where())
        except Exception:  # noqa: BLE001
            pass
        if not verify:
            c.check_hostname = False
            c.verify_mode = ssl.CERT_NONE
        try:
            c.set_alpn_protocols(["http/1.1"])
        except NotImplementedError:
            pass
        _CTX[verify] = c
    return c


class _MemTLS:
    """TLS over a plain socket whose first flight (the ClientHello) is cut into small TCP pieces - the same trick as Xray's
    `fragment` (packets=tlshello, length 100-200). Lets the scanner test an IP under the SAME conditions as a client that uses fragment."""
    LEN = (100, 200)
    GAP = (1, 3)   # ms between pieces

    def __init__(self, sock, ctx, host, timeout):
        self.sock = sock
        self._in, self._out = ssl.MemoryBIO(), ssl.MemoryBIO()
        self.tls = ctx.wrap_bio(self._in, self._out, server_hostname=host)
        sock.settimeout(timeout)
        first = True
        while True:
            try:
                self.tls.do_handshake()
                self._flush(False)
                return
            except ssl.SSLWantReadError:
                self._flush(first)
                first = False
                data = sock.recv(65536)
                if not data:
                    raise ConnectionResetError("closed during handshake")
                self._in.write(data)

    def _flush(self, cut):
        data = self._out.read()
        if not data:
            return
        if not cut:
            self.sock.sendall(data)
            return
        i = 0
        while i < len(data):
            n = random.randint(*self.LEN)
            self.sock.sendall(data[i:i + n])
            i += n
            if i < len(data):
                time.sleep(random.uniform(*self.GAP) / 1000.0)

    def sendall(self, data):
        self.tls.write(data)
        self._flush(False)

    def recv(self, n):
        while True:
            try:
                return self.tls.read(n)
            except ssl.SSLWantReadError:
                self._flush(False)
                data = self.sock.recv(65536)
                if data:
                    self._in.write(data)
                else:
                    self._in.write_eof()
            except (ssl.SSLZeroReturnError, ssl.SSLEOFError):
                return b""

    def settimeout(self, t):
        self.sock.settimeout(t)

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


@dataclasses.dataclass
class Exchange:
    status: int
    headers: dict
    body: bytes
    tcp_ms: float
    tls_ms: float
    ttfb_ms: float
    body_s: float


def http_exchange(ip, port, host, path, tls, timeout, verify, headers=None,
                  read_body=16384, headers_only=False, max_seconds=None, fragment=False) -> Exchange:
    """One real HTTP/1.1 GET to `ip` (TLS with SNI=host when tls). Raises ProbeError(code)."""
    sock = None
    try:
        t0 = time.perf_counter()
        sock = socket.create_connection((ip, port), timeout=timeout)
        t_tcp = time.perf_counter()
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        if tls:
            if fragment:
                sock = _MemTLS(sock, _ssl_ctx(verify), host, timeout)
            else:
                sock = _ssl_ctx(verify).wrap_socket(sock, server_hostname=host)
        t_tls = time.perf_counter()
        sock.settimeout(timeout)
        hdrs = {"Host": host, "User-Agent": UA, "Accept": "*/*", "Connection": "close"}
        hdrs.update(headers or {})
        req = f"GET {path} HTTP/1.1\r\n" + "".join(f"{k}: {v}\r\n" for k, v in hdrs.items()) + "\r\n"
        sock.sendall(req.encode())
        t_sent = time.perf_counter()
        buf = sock.recv(65536)
        if not buf:
            raise ProbeError("empty")
        t_first = time.perf_counter()
        while b"\r\n\r\n" not in buf and len(buf) < 32768:
            more = sock.recv(65536)
            if not more:
                break
            buf += more
        head, sep, body = buf.partition(b"\r\n\r\n")
        lines = head.decode("latin-1", "replace").split("\r\n")
        m = re.match(r"HTTP/\d(?:\.\d)? (\d{3})", lines[0])
        if not m or not sep:
            raise ProbeError("http")
        hmap = {}
        for ln in lines[1:]:
            k, _, v = ln.partition(":")
            hmap[k.strip().lower()] = v.strip()
        if not headers_only:
            try:
                want = min(int(hmap.get("content-length", read_body)), read_body)
            except ValueError:
                want = read_body
            while len(body) < want:
                if max_seconds and time.perf_counter() - t_first > max_seconds:
                    break
                try:
                    more = sock.recv(65536)
                except (socket.timeout, TimeoutError):
                    break
                if not more:
                    break
                body += more
        t_end = time.perf_counter()
        return Exchange(int(m.group(1)), hmap, body, (t_tcp - t0) * 1000, (t_tls - t_tcp) * 1000,
                        (t_first - t_sent) * 1000, t_end - t_first)
    except ProbeError:
        raise
    except Exception as e:  # noqa: BLE001 - every network failure becomes a reason code
        raise ProbeError(_classify(e)) from e
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def parse_trace(body: bytes) -> dict:
    out = {}
    for ln in body.decode("utf-8", "replace").splitlines():
        k, sep, v = ln.partition("=")
        if sep:
            out[k.strip()] = v.strip()
    return out


def trace_round(ip: str, cfg: Config) -> dict:
    ex = http_exchange(ip, cfg.port, cfg.host, "/cdn-cgi/trace", cfg.tls, cfg.timeout, cfg.verify, fragment=cfg.fragment)
    is_cf = ex.headers.get("server", "").lower().startswith("cloudflare") or "cf-ray" in ex.headers
    if not is_cf:
        raise ProbeError("notcf")
    if ex.status >= 500:
        raise ProbeError("http5xx")
    tr = parse_trace(ex.body)
    colo = tr.get("colo") or ex.headers.get("cf-ray", "").rsplit("-", 1)[-1]
    return {"tcp": ex.tcp_ms, "tls": ex.tls_ms, "ttfb": ex.ttfb_ms,
            "total": ex.tcp_ms + ex.tls_ms + ex.ttfb_ms, "colo": colo.upper()[:4], "status": ex.status}


def ws_test(ip: str, cfg: Config) -> bool:
    """Real WebSocket upgrade through this IP to your domain/path: success = HTTP 101."""
    key = base64.b64encode(os.urandom(16)).decode()
    try:
        ex = http_exchange(ip, cfg.port, cfg.host, cfg.ws_path or "/", cfg.tls, cfg.timeout, cfg.verify,
                           headers={"Connection": "Upgrade", "Upgrade": "websocket",
                                    "Sec-WebSocket-Key": key, "Sec-WebSocket-Version": "13"},
                           headers_only=True, fragment=cfg.fragment)
        return ex.status == 101
    except ProbeError:
        return False


def speed_test(ip: str, cfg: Config):
    """Real download through this IP (speed.cloudflare.com). Returns Mbps or None."""
    try:
        ex = http_exchange(ip, cfg.port, SPEED_HOST, f"/__down?bytes={cfg.speed_bytes}", cfg.tls,
                           max(cfg.timeout, 5.0), cfg.verify, read_body=cfg.speed_bytes + 65536, max_seconds=8, fragment=cfg.fragment)
    except ProbeError:
        return None
    if ex.status != 200 or len(ex.body) < 50_000 or ex.body_s <= 0:
        return None
    return round(len(ex.body) * 8 / ex.body_s / 1e6, 1)


def _tcp_try(ip, port, timeout):
    t = time.perf_counter()
    try:
        socket.create_connection((ip, port), timeout=timeout).close()
        return True, round((time.perf_counter() - t) * 1000), ""
    except Exception as e:  # noqa: BLE001
        return False, 0, _classify(e)


def has_ipv6(timeout: float = 4.0) -> bool:
    """True when this PC can open a TCP connection to Cloudflare over IPv6 (route check, then several Cloudflare addresses)."""
    try:
        u = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        u.connect((CF_V6_PROBES[0], 53))      # no packet is sent: fails at once when the system has no IPv6 route
        u.close()
    except OSError:
        return False
    probes = CF_V6_PROBES + list(iter_targets(Config(count=6, mode="random", family="v6")))
    with ThreadPoolExecutor(8) as ex:
        return any(ex.map(lambda ip: _tcp_try(ip, 443, timeout)[0], probes))


def _advice(d: dict, cfg: Config) -> list:
    v, port = d["verdict"], d["port"]
    op = ("پورت‌های بازِ روی شبکه‌ی تو: " + "، ".join(map(str, d["open_ports"])) + ". یکی از همین‌ها را امتحان کن.") if d.get("open_ports") else ""
    if v == "ok":
        return [f"اتصال به کلودفلر سالم است (دامنه‌ی تست: {d['best_host']})."]
    if v == "cert":
        return ["پاسخ کلودفلر می‌رسد ولی گواهی‌اش روی این سیستم تأیید نمی‌شود (ریشه‌ی گواهی در ویندوز نیست یا ساعت سیستم غلط است). اسکن بدون بررسی گواهی ادامه پیدا می‌کند؛ کلودفلر بودن پاسخ همچنان از روی هدرها و /cdn-cgi/trace کنترل می‌شود."]
    if v == "tcp":
        return [f"اتصال TCP به هیچ‌کدام از آی‌پی‌های نمونه‌ی کلودفلر روی پورت {port} برقرار نشد. یعنی اینترنت قطع است، یا VPN/پروکسی/TUN روشن است، یا فایروال/آنتی‌ویروس مانع می‌شود، یا این پورت روی شبکه‌ات بسته است. " + op]
    if v == "tls":
        return [f"TCP وصل می‌شود ولی هندشیک TLS قطع یا کند می‌شود؛ یعنی دامنه‌ی تست (SNI) یا پورت {port} روی این شبکه فیلتر است. دامنه‌ی دیگری (مثل www.cloudflare.com) یا پورت دیگری را امتحان کن. " + op]
    if v == "notcf":
        return ["TLS برقرار می‌شود ولی جواب از کلودفلر نیست؛ احتمالاً پراکسی، فیلتر یا آنتی‌ویروس وسط راه است."]
    return ["اتصال برقرار می‌شود ولی پاسخ HTTP معتبر نمی‌رسد. دامنه‌ی تست یا پورت را عوض کن."]


def diagnose(cfg: Config, samples=None, snis=None, probe_ports=None, workers: int = 12) -> dict:
    """Step-by-step check of THIS network: TCP → TLS(+certificate) → HTTP, for several SNI names.
    Tells which stage breaks and (when possible) which setting fixes it."""
    if samples is None:
        samples = ["1.1.1.1", "1.0.0.1"] + list(iter_targets(Config(count=4, mode="random")))
    if snis is None:
        snis = []
        for h in (cfg.host, SPEED_HOST, "www.cloudflare.com", "cloudflare.com"):
            if h not in snis:
                snis.append(h)
    d = {"at": time.time(), "port": cfg.port, "samples": [], "sni": [], "open_ports": [], "verdict": "", "best_host": None, "advice": []}
    with ThreadPoolExecutor(workers) as ex:
        tcp = list(ex.map(lambda ip: _tcp_try(ip, cfg.port, min(cfg.timeout, 4)), samples))
        d["samples"] = [{"ip": ip, "tcp": ok, "ms": ms, "err": err} for ip, (ok, ms, err) in zip(samples, tcp)]
        live = [x["ip"] for x in d["samples"] if x["tcp"]]

        def one(job):
            sni, ip = job
            c = dataclasses.replace(cfg, host=sni)
            try:
                trace_round(ip, c)
                return sni, "ok"
            except ProbeError as e:
                if e.code == "cert" and cfg.verify:
                    try:
                        trace_round(ip, dataclasses.replace(c, verify=False))
                        return sni, "cert_only"
                    except ProbeError as e2:
                        return sni, e2.code
                return sni, e.code

        res = list(ex.map(one, [(h, ip) for h in snis for ip in live]))
        for h in snis:
            codes = [c for n, c in res if n == h]
            d["sni"].append({"host": h, "ok": codes.count("ok"), "cert_only": codes.count("cert_only"),
                             "errors": dict(collections.Counter(c for c in codes if c not in ("ok", "cert_only")))})
        if not live:
            d["verdict"] = "tcp"
        else:
            okb = max(d["sni"], key=lambda x: (x["ok"], x["host"] == cfg.host))
            cob = max(d["sni"], key=lambda x: (x["cert_only"], x["host"] == cfg.host))
            if okb["ok"] > 0:
                d["verdict"], d["best_host"] = "ok", (cfg.host if any(x["host"] == cfg.host and x["ok"] > 0 for x in d["sni"]) else okb["host"])
            elif cob["cert_only"] > 0:
                d["verdict"], d["best_host"] = "cert", (cfg.host if any(x["host"] == cfg.host and x["cert_only"] > 0 for x in d["sni"]) else cob["host"])
            else:
                allc = collections.Counter()
                for x in d["sni"]:
                    allc.update(x["errors"])
                top = allc.most_common(1)[0][0] if allc else "http"
                d["verdict"] = "tls" if top in ("tls", "timeout", "reset", "empty", "unreachable", "refused") else ("notcf" if top == "notcf" else "http")
        if d["verdict"] in ("tcp", "tls"):
            ports = [p for p in (TLS_PORTS + PLAIN_PORTS if probe_ports is None else probe_ports)]
            ips = [x for x in samples if x not in ("1.1.1.1", "1.0.0.1")][:2] or samples[:1]
            jobs = [(ip, p) for p in ports for ip in ips]
            ans = list(ex.map(lambda j: _tcp_try(j[0], j[1], 2.0)[0], jobs))
            d["open_ports"] = sorted({j[1] for j, ok in zip(jobs, ans) if ok})
    d["advice"] = _advice(d, cfg)
    return d


def scan_ip(ip: str, cfg: Config, stop: threading.Event | None = None):
    """Returns (result_dict | None, reason). Fails fast: a dead IP costs one timeout, not all rounds."""
    rounds, reason = [], "error"
    for i in range(cfg.rounds):
        if stop is not None and stop.is_set():
            return None, "stopped"
        try:
            rounds.append(trace_round(ip, cfg))
        except ProbeError as e:
            reason = e.code
            if i == 0:
                return None, reason
    need = max(1, math.ceil(cfg.rounds * 2 / 3))
    if len(rounds) < need:
        return None, "unstable"
    totals = [r["total"] for r in rounds]
    med = statistics.median(totals)
    jitter = statistics.pstdev(totals) if len(totals) > 1 else 0.0
    loss = 1 - len(rounds) / cfg.rounds
    mid = lambda k: round(statistics.median(r[k] for r in rounds))  # noqa: E731
    res = {
        "ip": ip, "port": cfg.port, "colo": next((r["colo"] for r in rounds if r["colo"]), ""),
        "tcp": mid("tcp"), "tls": mid("tls"), "ttfb": mid("ttfb"), "total": round(med),
        "jitter": round(jitter), "loss": round(loss * 100), "ws": None, "speed": None,
        "score": round(max(0.0, 100 - med / 8 - jitter / 2 - loss * 40)),
    }
    if cfg.ws:
        res["ws"] = ws_test(ip, cfg)
    return res, "ok"


# ───────────────────────────── target generation ─────────────────────────────
def parse_targets(text: str):
    exact, nets = [], []
    for tok in re.split(r"[\s,;]+", text or ""):
        if not tok:
            continue
        try:
            if "/" in tok:
                nets.append(ipaddress.ip_network(tok, strict=False))
            else:
                exact.append(str(ipaddress.ip_address(tok)))
        except ValueError:
            continue
    return exact, nets


def _host_in(block, rng):
    base, size = int(block.network_address), block.num_addresses
    if block.version == 6:
        # Cloudflare IPv6 hosts look like 2606:4700:XXXX::6815:XXXX -> random /48 inside the block + random low 32 bits
        if block.prefixlen <= 48:
            hi = base + (rng.randrange(1 << (48 - block.prefixlen)) << 80)
            return str(ipaddress.IPv6Address(hi + rng.randrange(1, 1 << 32)))
        return str(ipaddress.IPv6Address(base + rng.randrange(1, max(2, size))))
    for _ in range(8):
        off = rng.randrange(size)
        if size < 256 or off % 256 not in (0, 255):
            break
    return str(ipaddress.IPv4Address(base + off))


def iter_targets(cfg: Config, rng: random.Random | None = None):
    rng = rng or new_rng()
    exact, nets = parse_targets(cfg.custom)
    if not exact and not nets:
        if cfg.family in ("v4", "both"):
            nets += [ipaddress.ip_network(c) for c in CF_RANGES]
        if cfg.family in ("v6", "both"):
            nets += [ipaddress.ip_network(c) for c in CF_RANGES_V6]
    seen, n = set(), 0
    for ip in exact:
        if ip not in seen and n < cfg.count:
            seen.add(ip)
            n += 1
            yield ip
    if not nets or n >= cfg.count:
        return
    blocks, blocks6 = [], [x for x in nets if x.version == 6]
    for net in nets:
        if net.version == 4:
            blocks.extend(net.subnets(new_prefix=24) if net.prefixlen < 24 else [net])
    if not blocks and not blocks6:
        return
    misses, limit = 0, cfg.count * 20 + 1000
    order = blocks[:]
    rng.shuffle(order)
    i = j = 0
    while n < cfg.count and misses < limit:
        if blocks6 and (not blocks or j % 2):          # IPv4 + IPv6: alternate, so both families get an equal share
            b = rng.choice(blocks6)
        else:
            b = order[i % len(order)] if cfg.mode == "spread" else rng.choice(blocks)
            i += 1
        j += 1
        ip = _host_in(b, rng)
        if ip in seen:
            misses += 1
            continue
        seen.add(ip)
        n += 1
        yield ip


def neighbours(ip: str, k: int, seen: set, rng: random.Random):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return []
    v6 = a.version == 6
    base, out = (int(a) & ~0xFFFF) if v6 else (int(a) & ~255), []
    for _ in range(k * 3):
        c = str(ipaddress.IPv6Address(base + rng.randint(1, 0xFFFE)) if v6 else ipaddress.IPv4Address(base + rng.randint(1, 254)))
        if c not in seen:
            out.append(c)
        if len(out) >= k:
            break
    return out


# ───────────────────────────── the scan job ─────────────────────────────
def net_info(timeout: float = 4.0) -> dict:
    """Who does Cloudflare think we are? (shows whether a VPN is on)"""
    try:
        ex = http_exchange("1.1.1.1", 443, "one.one.one.one", "/cdn-cgi/trace", True, timeout, True)
        tr = parse_trace(ex.body)
        is_cf = ex.headers.get("server", "").lower().startswith("cloudflare") or "cf-ray" in ex.headers
        if ex.status != 200 or not is_cf or not tr.get("ip"):
            return {"ok": False, "error": "notcf"}     # a proxy / filter answered, not Cloudflare
        return {"ok": True, "ip": tr.get("ip", ""), "loc": tr.get("loc", ""), "colo": tr.get("colo", "")}
    except ProbeError as e:
        return {"ok": False, "error": e.code}



# ════════════════════════════════════════════════════════════════════════════
#  PART 1b - automatic bypass: reach the panel / worker through a clean Cloudflare IP (no VPN needed)
# ════════════════════════════════════════════════════════════════════════════
ROUTE_IPS: list = []     # clean IPs found by the scan; used to reach the panel when pages.dev / workers.dev is blocked
ROUTES: dict = {}        # "host:port" -> list of (ip, fragment, verify) that work on this network
DIRECT_BAD: dict = {}    # "host:port" -> True when the normal connection is blocked (skip it, saves seconds)
NET_LOG = lambda m: None  # noqa: E731


def set_net_log(fn):
    global NET_LOG
    NET_LOG = fn


def _dechunk(b: bytes) -> bytes:
    out, i = b"", 0
    while True:
        j = b.find(b"\r\n", i)
        if j < 0:
            break
        try:
            size = int(b[i:j].split(b";")[0].strip() or b"0", 16)
        except ValueError:
            break
        if size == 0:
            break
        out += b[j + 2:j + 2 + size]
        i = j + 2 + size + 2
    return out


def raw_http(method, ip, port, host, path, headers, body, timeout, verify, fragment):
    """A full HTTP/1.1 request to `ip` with SNI/Host = `host` (optionally with the TLS ClientHello cut into pieces).
    Returns (status, reason, header_text, header_dict, body_bytes). Raises ProbeError."""
    sock = None
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        if fragment:
            sock = _MemTLS(sock, _ssl_ctx(verify), host, timeout)
        else:
            sock = _ssl_ctx(verify).wrap_socket(sock, server_hostname=host)
        sock.settimeout(timeout)
        data = body.encode() if isinstance(body, str) else (body or b"")
        hdrs = {"Host": host if port == 443 else f"{host}:{port}", "Accept": "*/*", "Accept-Encoding": "identity", "Connection": "close"}
        for k, v in (headers or {}).items():
            if k.lower() not in ("host", "accept-encoding", "connection", "content-length", "transfer-encoding"):
                hdrs[k] = v
        if data or method.upper() in ("POST", "PUT", "PATCH"):
            hdrs["Content-Length"] = str(len(data))
        head = f"{method.upper()} {path} HTTP/1.1\r\n" + "".join(f"{k}: {v}\r\n" for k, v in hdrs.items()) + "\r\n"
        sock.sendall(head.encode("latin-1") + data)
        def complete(b):
            h, sep, rest = b.partition(b"\r\n\r\n")
            if not sep:
                return False
            low = h.lower()
            m = re.search(rb"content-length:\s*(\d+)", low)
            if m:
                return len(rest) >= int(m.group(1))
            return b"transfer-encoding: chunked" in low and rest.endswith(b"0\r\n\r\n")
        buf = b""
        while True:
            try:
                chunk = sock.recv(65536)
            except (ssl.SSLEOFError, ssl.SSLZeroReturnError):
                break
            except (socket.timeout, TimeoutError, OSError):
                if complete(buf):
                    break
                raise
            if not chunk:
                break
            buf += chunk
            if complete(buf) or len(buf) > 30_000_000:
                break
        h, sep, rest = buf.partition(b"\r\n\r\n")
        if not sep:
            raise ProbeError("http")
        lines = h.decode("latin-1", "replace").split("\r\n")
        m = re.match(r"HTTP/\d(?:\.\d)? (\d{3})\s*(.*)", lines[0])
        if not m:
            raise ProbeError("http")
        hmap = {}
        for ln in lines[1:]:
            k, _, v = ln.partition(":")
            k = k.strip().lower()
            hmap[k] = (hmap[k] + ", " + v.strip()) if k in hmap else v.strip()
        if "chunked" in hmap.get("transfer-encoding", "").lower():
            rest = _dechunk(rest)
        enc = hmap.get("content-encoding", "").lower()
        try:
            if enc == "gzip":
                rest = gzip.decompress(rest)
            elif enc == "deflate":
                rest = zlib.decompress(rest)
        except Exception:  # noqa: BLE001
            pass
        return int(m.group(1)), m.group(2), "\r\n".join(lines[1:]) + "\r\n", hmap, rest
    except ProbeError:
        raise
    except Exception as e:  # noqa: BLE001
        raise ProbeError(_classify(e)) from e
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


class _RawStub:
    """Just enough of a urllib3 response for requests' cookie handling."""

    def __init__(self, msg):
        self._original_response = types.SimpleNamespace(msg=msg)

    def close(self):
        pass

    def release_conn(self):
        pass


def _find_route(host: str, port: int, skip=()):
    """Try the scanned clean IPs (with and without TLS fragment) until one reaches `host` through Cloudflare."""
    ips = []
    for ip in list(ROUTE_IPS) + list(iter_targets(Config(count=4, mode="random"))):
        if ip not in ips and ip not in skip:
            ips.append(ip)
    jobs = [(ip, frag) for ip in ips[:16] for frag in (True, False)]

    def probe(job):
        ip, frag = job
        for verify in (True, False):
            try:
                ex = http_exchange(ip, port, host, "/", True, 6.0, verify, headers_only=True, fragment=frag)
            except ProbeError as e:
                if e.code == "cert" and verify:
                    continue
                return None
            if ex.headers.get("server", "").lower().startswith("cloudflare") or "cf-ray" in ex.headers:
                return (ip, frag, verify)
            return None
        return None
    pool = ThreadPoolExecutor(10)
    futs = [pool.submit(probe, j) for j in jobs]
    try:
        for f in as_completed(futs):
            r = f.result()
            if r:
                return r
    finally:
        pool.shutdown(wait=False, cancel_futures=True)
    return None


class SmartAdapter(requests.adapters.HTTPAdapter):
    """Normal connection first; when the address is blocked / hijacked on this network, the request is sent straight to a clean
    Cloudflare IP instead (SNI + Host stay the panel's own name). Fully automatic, no VPN."""

    def _via(self, request, route, timeout):
        ip, frag, verify = route
        u = urlparse(request.url)
        st, reason, htext, hmap, content = raw_http(request.method, ip, u.port or 443, u.hostname, request.path_url,
                                                    dict(request.headers), request.body, timeout, verify, frag)
        resp = requests.Response()
        resp.status_code, resp.reason = st, reason
        resp.headers = requests.structures.CaseInsensitiveDict(hmap)
        resp._content, resp._content_consumed = content, True
        resp.url, resp.request = request.url, request
        resp.encoding = requests.utils.get_encoding_from_headers(resp.headers)
        resp.raw = _RawStub(email.message_from_string(htext, _class=http.client.HTTPMessage))   # lets Session keep Set-Cookie
        return resp

    def send(self, request, **kw):
        u = urlparse(request.url)
        host, port = u.hostname or "", u.port or 443
        key = f"{host}:{port}"
        tmo = kw.get("timeout")
        tmo = float((tmo[0] if isinstance(tmo, tuple) else tmo) or 15)
        routes = ROUTES.setdefault(key, [])
        for route in list(routes):                         # routes that worked before (a fragmented handshake can reset: try twice)
            for _ in range(2):
                try:
                    return self._via(request, route, tmo)
                except ProbeError:
                    pass
            if route in routes:
                routes.remove(route)
        if not DIRECT_BAD.get(key):
            try:
                kw2 = dict(kw)
                kw2["timeout"] = min(tmo, 6.0)
                resp = super().send(request, **kw2)
                if resp.headers.get("server", "").lower().startswith("cloudflare") or "cf-ray" in resp.headers:
                    return resp
                NET_LOG(f"{host}: the direct answer is not from Cloudflare (DNS / filter interference) - routing through clean IPs.")
            except requests.RequestException as e:
                NET_LOG(f"{host}: direct connection failed ({type(e).__name__}) - routing through clean IPs.")
            DIRECT_BAD[key] = True
        tried = {r[0] for r in routes}
        for _ in range(4):
            route = _find_route(host, port, tried)
            if not route:
                break
            tried.add(route[0])
            try:
                resp = self._via(request, route, tmo)
            except ProbeError:
                continue
            routes.append(route)
            NET_LOG(f"{host}: connected through clean IP {route[0]}" + (" with TLS fragment." if route[1] else "."))
            return resp
        raise requests.ConnectionError(f"{host}: not reachable directly nor through any clean IP")


def web_session():
    """requests session for the panel / worker / subscription (self-routing when the address is blocked)."""
    s = requests.Session()
    s.mount("https://", SmartAdapter())
    return s


# ════════════════════════════════════════════════════════════════════════════
#  PART 2 - Cloudflare API client (taken unchanged from aminium_deployer.py)
# ════════════════════════════════════════════════════════════════════════════
_PROXY_ON = False


def apply_proxy(p: str) -> str:
    """Route the HTTP(S) requests of the app (panel / worker / subscription) through a local proxy such as v2rayN's.
    The IP scan uses raw sockets, so it always stays direct; api.cloudflare.com is kept direct too."""
    global _PROXY_ON
    p = (p or "").strip()
    keys = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY")
    if not p:
        if _PROXY_ON:
            for k in keys:
                os.environ.pop(k, None)
                os.environ.pop(k.lower(), None)
            _PROXY_ON = False
        return ""
    if "://" not in p:
        p = "http://" + p
    for k in keys:
        os.environ[k] = p
        os.environ[k.lower()] = p
    direct = "api.cloudflare.com,localhost,127.0.0.1"
    os.environ["NO_PROXY"] = os.environ["no_proxy"] = direct
    _PROXY_ON = True
    return p


def rnd(n=16, alphabet=string.ascii_letters + string.digits) -> str:
    return "".join(secrets.choice(alphabet) for _ in range(n))


class CFError(Exception):
    pass


class CF:
    """Tiny Cloudflare API client."""

    def __init__(self, token: str, log, email: str = ""):
        self.s = requests.Session()
        self.global_key = bool(email)
        if email:
            self.s.headers.update({"X-Auth-Email": email, "X-Auth-Key": token})
        else:
            self.s.headers.update({"Authorization": f"Bearer {token}"})
        self.log = log

    def req(self, method, path, **kw):
        url = path if path.startswith("http") else API + path
        for attempt in range(3):
            try:
                r = self.s.request(method, url, timeout=120, **kw)
                break
            except requests.RequestException as e:
                if attempt == 2:
                    raise CFError(f"Network error: {e}")
                time.sleep(2)
        try:
            data = r.json()
        except Exception:
            raise CFError(f"HTTP {r.status_code}: {r.text[:400]}")
        if not data.get("success", False):
            errs = data.get("errors") or []
            msg = "; ".join(f"[{e.get('code')}] {e.get('message')}" for e in errs) or r.text[:400]
            err = CFError(f"{method} {path} -> HTTP {r.status_code}: {msg}")
            err.codes = [e.get("code") for e in errs]
            raise err
        return data

    # ---- account / token
    def verify(self):
        if self.global_key:
            r = self.req("GET", "/user")["result"]
            return {"status": f"active (global key, {r.get('email')})"}
        return self.req("GET", "/user/tokens/verify")["result"]

    def accounts(self):
        return self.req("GET", "/accounts?per_page=50")["result"]

    # ---- create a full-permission token (needs Global Key or a token with "API Tokens: Edit")
    def create_full_token(self, acc_id, name):
        groups = self.req("GET", "/user/tokens/permission_groups")["result"]
        wanted = {
            "kv": lambda n: "kv" in n and "write" in n,
            "d1": lambda n: n.startswith("d1") and "write" in n,
            "pages": lambda n: "pages" in n and "write" in n,
            "scripts": lambda n: n == "workers scripts write",
            "settings": lambda n: n == "account settings read",
            "analytics": lambda n: n == "account analytics read",
        }
        picked = {}
        for g in groups:
            n = g.get("name", "").lower()
            scopes = " ".join(g.get("scopes") or [])
            if "com.cloudflare.api.account" not in scopes:
                continue
            for k, fn in wanted.items():
                if k not in picked and fn(n):
                    picked[k] = g
        missing = [k for k in ("kv", "d1", "pages") if k not in picked]
        if missing:
            raise CFError(f"Permission groups not found: {', '.join(missing)}")
        for k, g in picked.items():
            self.log(f"  + {g['name']}")
        body = {
            "name": name,
            "policies": [
                {
                    "effect": "allow",
                    "resources": {f"com.cloudflare.api.account.{acc_id}": "*"},
                    "permission_groups": [{"id": g["id"]} for g in picked.values()],
                }
            ],
        }
        return self.req("POST", "/user/tokens", json=body)["result"]["value"]

    # ---- KV
    def kv_get_or_create(self, acc, title):
        res = self.req("GET", f"/accounts/{acc}/storage/kv/namespaces?per_page=100")["result"]
        for ns in res:
            if ns["title"] == title:
                self.log(f"KV namespace exists: {title}")
                return ns["id"]
        ns = self.req("POST", f"/accounts/{acc}/storage/kv/namespaces", json={"title": title})["result"]
        self.log(f"KV namespace created: {title}")
        return ns["id"]

    # ---- D1
    def d1_get_or_create(self, acc, name):
        res = self.req("GET", f"/accounts/{acc}/d1/database?per_page=100")["result"]
        for db in res:
            if db["name"] == name:
                self.log(f"D1 database exists: {name}")
                return db["uuid"]
        db = self.req("POST", f"/accounts/{acc}/d1/database", json={"name": name})["result"]
        self.log(f"D1 database created: {name}")
        return db["uuid"]

    # ---- Pages
    def pages_project(self, acc, name):
        try:
            return self.req("GET", f"/accounts/{acc}/pages/projects/{name}")["result"]
        except CFError:
            return None

    def pages_create(self, acc, name):
        return self.req(
            "POST",
            f"/accounts/{acc}/pages/projects",
            json={"name": name, "production_branch": "main"},
        )["result"]

    def pages_configure(self, acc, name, kv_id, d1_id, env_vars):
        cfg = {
            "compatibility_date": "2024-09-23",
            "kv_namespaces": {"KV": {"namespace_id": kv_id}},
            "env_vars": env_vars,
        }
        if d1_id:
            cfg["d1_databases"] = {"DB": {"id": d1_id}}
        body = {"deployment_configs": {"production": cfg, "preview": cfg}}
        return self.req("PATCH", f"/accounts/{acc}/pages/projects/{name}", json=body)["result"]

    def pages_deploy(self, acc, name, files: dict):
        """files: {"_worker.js": bytes, "index.html": bytes, ...}"""
        manifest = {}
        parts = []
        for fname, content in files.items():
            if fname == "_worker.js":
                parts.append(("_worker.js", ("_worker.js", content, "application/javascript")))
                continue
            h = file_hash(fname, content)
            manifest["/" + fname] = h
            ctype = mimetypes.guess_type(fname)[0] or "application/octet-stream"
            parts.append((h, (fname, content, ctype)))
        parts.insert(0, ("manifest", (None, json.dumps(manifest))))
        parts.insert(1, ("branch", (None, "main")))
        return self.req("POST", f"/accounts/{acc}/pages/projects/{name}/deployments", files=parts)["result"]

    def pages_deployment_status(self, acc, name, dep_id):
        return self.req("GET", f"/accounts/{acc}/pages/projects/{name}/deployments/{dep_id}")["result"]

    # ---- Workers (workers.dev)
    def workers_account_subdomain(self, acc, suggest):
        """Return the account's workers.dev subdomain, registering one if the account has none yet."""
        try:
            r = self.req("GET", f"/accounts/{acc}/workers/subdomain").get("result") or {}
            if r.get("subdomain"):
                return r["subdomain"]
        except CFError:
            pass
        base = re.sub(r"[^a-z0-9-]", "", suggest.lower()).strip("-")[:30] or "aminium"
        last = None
        for cand in (base, f"{base}-{rnd(4, string.ascii_lowercase + string.digits)}"):
            try:
                r = self.req("PUT", f"/accounts/{acc}/workers/subdomain", json={"subdomain": cand})["result"]
                self.log(f"workers.dev subdomain registered: {r['subdomain']}")
                return r["subdomain"]
            except CFError as e:
                last = e
        raise last

    def workers_deploy(self, acc, name, js: bytes, kv_id, d1_id, env_vars):
        """Upload an ES-module Worker with KV / D1 bindings and variables / secrets in one multipart request."""
        bindings = [{"type": "kv_namespace", "name": "KV", "namespace_id": kv_id}]
        if d1_id:
            bindings.append({"type": "d1", "name": "DB", "id": d1_id})
        for k, v in env_vars.items():
            bindings.append({"type": v["type"], "name": k, "text": v["value"]})
        meta = {
            "main_module": "worker.js",
            "compatibility_date": "2024-09-23",
            "bindings": bindings,
        }
        parts = [
            ("metadata", (None, json.dumps(meta), "application/json")),
            ("worker.js", ("worker.js", js, "application/javascript+module")),
        ]
        return self.req("PUT", f"/accounts/{acc}/workers/scripts/{name}", files=parts)["result"]

    # ---- custom domain (the domain's zone must be in the same Cloudflare account)
    def zone_for(self, hostname):
        parts = hostname.split(".")
        for i in range(len(parts) - 1):
            cand = ".".join(parts[i:])
            res = self.req("GET", f"/zones?name={cand}&per_page=1")["result"]
            if res:
                return res[0]["id"]
        return None

    def workers_attach_domain(self, acc, name, hostname, zone_id):
        return self.req(
            "PUT", f"/accounts/{acc}/workers/domains",
            json={"hostname": hostname, "service": name, "zone_id": zone_id, "environment": "production"},
        )

    def pages_attach_domain(self, acc, name, hostname, zone_id, target):
        self.req("POST", f"/accounts/{acc}/pages/projects/{name}/domains", json={"name": hostname})
        try:
            self.req("POST", f"/zones/{zone_id}/dns_records",
                     json={"type": "CNAME", "name": hostname, "content": target, "proxied": True})
        except CFError as e:
            self.log(f"DNS record not created (it may already exist): {e}")

    def workers_delete(self, acc, name):
        return self.req("DELETE", f"/accounts/{acc}/workers/scripts/{name}", params={"force": "true"})

    def pages_delete(self, acc, name):
        return self.req("DELETE", f"/accounts/{acc}/pages/projects/{name}")

    def workers_enable_subdomain(self, acc, name):
        return self.req(
            "POST", f"/accounts/{acc}/workers/scripts/{name}/subdomain",
            json={"enabled": True, "previews_enabled": False},
        )

    def workers_set_cron(self, acc, name, cron="*/15 * * * *"):
        return self.req("PUT", f"/accounts/{acc}/workers/scripts/{name}/schedules", json=[{"cron": cron}])


def file_hash(fname: str, content: bytes) -> str:
    import base64

    ext = Path(fname).suffix.lstrip(".")
    payload = base64.b64encode(content).decode() + ext
    if blake3:
        return blake3.blake3(payload.encode()).hexdigest()[:32]
    return hashlib.sha256(payload.encode()).hexdigest()[:32]


def fetch_sub_link(base: str, panel: str, password: str, log, wait: int = 90, ws_path: str = ""):
    """Log in to the freshly deployed panel, make sure a user exists, return (sub_url, user_name)."""
    s = web_session()
    s.headers["User-Agent"] = "Mozilla/5.0 (AminiumDeployer)"
    api = f"{base}{panel}/api"
    deadline = time.time() + wait
    last = ""
    while True:
        try:
            r = s.post(api + "/login", json={"password": password}, timeout=20)
            if r.status_code == 200 and r.json().get("ok"):
                break
            last = f"HTTP {r.status_code}"
            if r.status_code == 401:
                raise CFError("Panel rejected the admin password")
        except requests.RequestException as e:
            last = str(e)
        except ValueError:
            snippet = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", r.text))[:160]
            last = f"HTTP {r.status_code}: {snippet}"
            if "1101" in r.text or "Worker threw" in r.text:
                log("Cloudflare error 1101 = the Worker crashed. Open the Worker > Observability > Logs "
                    "(or 'Real-time logs') and send me the red error line.")
        if time.time() > deadline:
            raise CFError(f"Panel not reachable ({last})")
        log(f"Waiting for the panel... ({last})")
        time.sleep(5)
    state = s.get(api + "/state", timeout=20).json()
    if ws_path and (state.get("settings") or {}).get("wsPath") != ws_path:
        r = s.post(api + "/settings", json={"wsPath": ws_path}, timeout=20)
        if r.status_code == 200:
            log(f"WebSocket path set to {ws_path}")
        else:
            log(f"Could not set WebSocket path ({r.status_code}): {r.text[:200]}")
    users = state.get("users") or []
    user = next((u for u in users if u.get("enabled") is not False), None)
    if user is None:
        r = s.post(api + "/users", json={"name": "user1", "days": 0, "limitGB": 0}, timeout=20)
        r.raise_for_status()
        user = r.json()["user"]
        log("No users yet: created 'user1' (unlimited).")
    return f"{base}/sub/{user['token']}", user.get("name", "")


def load_source(path: str) -> dict:
    """Load files from a zip or a folder. Must contain _worker.js."""
    p = Path(path)
    files = {}
    if p.is_file() and p.suffix.lower() == ".zip":
        with zipfile.ZipFile(p) as z:
            for info in z.infolist():
                if info.is_dir():
                    continue
                name = info.filename.replace("\\", "/")
                # strip a single top-level folder if present
                files[name] = z.read(info)
        # normalise a common top folder
        names = list(files)
        if "_worker.js" not in files:
            tops = {n.split("/")[0] for n in names}
            if len(tops) == 1:
                top = tops.pop() + "/"
                files = {n[len(top):]: c for n, c in files.items() if n.startswith(top)}
    elif p.is_dir():
        for f in p.rglob("*"):
            if f.is_file():
                files[f.relative_to(p).as_posix()] = f.read_bytes()
    else:
        raise CFError("Source must be a .zip file or a folder")
    if "_worker.js" not in files:
        raise CFError("_worker.js not found in the selected source")
    return files



# ════════════════════════════════════════════════════════════════════════════
#  PART 3 - glue: English diagnosis text, scan job, panel client
# ════════════════════════════════════════════════════════════════════════════
def _advice(d: dict, cfg: Config) -> list:  # noqa: F811  (replaces the Persian text of cf_scanner)
    v, port = d["verdict"], d["port"]
    op = ("Ports open on your network: " + ", ".join(map(str, d["open_ports"])) + ". Try one of them.") if d.get("open_ports") else ""
    if v == "ok":
        return [f"Connection to Cloudflare is healthy (test domain: {d['best_host']})."]
    if v == "cert":
        return ["Cloudflare answers but its certificate cannot be verified on this PC (missing root cert or wrong clock). "
                "Scanning continues without certificate check; Cloudflare is still confirmed by headers and /cdn-cgi/trace."]
    if v == "tcp":
        return [f"TCP to Cloudflare sample IPs on port {port} failed: internet down, a VPN/proxy/TUN is on, a firewall/antivirus blocks it, "
                f"or this port is closed on your network. " + op]
    if v == "tls":
        return [f"TCP connects but the TLS handshake dies: the test domain (SNI) or port {port} is filtered here. "
                f"Try another domain (e.g. www.cloudflare.com) or another port. " + op]
    if v == "notcf":
        return ["TLS works but the answer is not from Cloudflare: a proxy, filter or antivirus sits in the middle."]
    return ["Connected, but no valid HTTP answer came back. Change the test domain or the port."]


class ScanJob:
    """Same algorithm as cf_scanner.Scan, with English log lines and a plain log callback."""

    def __init__(self, cfg: Config, log):
        self.cfg = cfg
        self._log = log
        self.lock = threading.RLock()
        self.stop = threading.Event()
        self.soft = threading.Event()
        self.results: list = []
        self.reasons = collections.Counter()
        self.tested = 0
        self.total = 0
        self.phase = "idle"
        self.started = 0.0
        self.finished = 0.0
        self.rng = new_rng()
        self.seen: set = set()
        self.cert_fails = 0
        self.diag: dict | None = None
        self.diag_on_empty = True

    def log(self, msg):
        self._log(msg)

    def snapshot(self):
        with self.lock:
            end = self.finished or time.time()
            return {"phase": self.phase, "tested": self.tested, "total": self.total,
                    "found": len(self.results), "elapsed": round(end - self.started, 1) if self.started else 0,
                    "results": list(self.results), "reasons": dict(self.reasons)}

    def _worker(self, q: queue.PriorityQueue):
        cfg = self.cfg
        while True:
            try:
                _, _, ip = q.get(timeout=0.25)
            except queue.Empty:
                if self.phase != "scanning":
                    return
                continue
            try:
                if self.stop.is_set() or self.soft.is_set():
                    continue
                res, reason = scan_ip(ip, cfg, self.stop)
                with self.lock:
                    self.tested += 1
                    if res:
                        self.results.append(res)
                        if cfg.target and len(self.results) >= cfg.target:
                            self.soft.set()
                    elif reason != "stopped":
                        self.reasons[reason] += 1
                        if reason == "cert" and cfg.verify and not self.results:
                            self.cert_fails += 1
                            if self.cert_fails == 8:
                                cfg.verify = False
                                self.log("Certificate cannot be verified on this system: check turned off, scan continues.")
                if res and cfg.neighbors and not self.soft.is_set():
                    with self.lock:
                        extra = neighbours(ip, 4, self.seen, self.rng)
                        cap = int(cfg.count * 1.5)
                        extra = extra[: max(0, cap - len(self.seen))]
                        self.seen.update(extra)
                        self.total += len(extra)
                    for e in extra:
                        q.put((0, self.rng.random(), e))
            finally:
                q.task_done()

    def run(self):
        cfg = self.cfg
        self.started = time.time()
        try:
            if cfg.family != "v4" and not cfg.custom.strip():
                self.phase = "diagnosing"
                self.log("Checking IPv6 connectivity...")
                if has_ipv6():
                    self.log("IPv6 works on this network.")
                elif cfg.family == "v6":
                    self.log("ERROR: this network has no working IPv6 (most ISPs in Iran do not offer it) - pick 'IPv4 + IPv6' or 'IPv4'.")
                    self.phase = "done"
                    return
                else:
                    self.log("No working IPv6 on this network: continuing with IPv4 only.")
                    cfg.family = "v4"
            if cfg.auto:
                self.phase = "diagnosing"
                self.log("Checking the connection to Cloudflare...")
                v6s = (CF_V6_PROBES + list(iter_targets(dataclasses.replace(cfg, count=4, mode="random", custom="")))) if cfg.family == "v6" else None
                d = self.diag = diagnose(cfg, samples=v6s)
                for a in d["advice"]:
                    self.log(a)
                if d["verdict"] in ("ok", "cert"):
                    best = d["best_host"]
                    if best and best != cfg.host:
                        self.log(f"'{cfg.host}' does not answer on this network; scanning with '{best}' instead.")
                        cfg.host = best
                        if cfg.ws:
                            cfg.ws = False
                            self.log("WebSocket test disabled for this run (your domain could not be tested).")
                    if d["verdict"] == "cert" and cfg.verify:
                        cfg.verify = False
                elif d["verdict"] == "tcp":
                    self.phase = "done"
                    return
            self.phase = "scanning"
            self.log(f"Scan started: {cfg.host}:{cfg.port} ({'TLS' if cfg.tls else 'no TLS'}), {cfg.rounds} rounds per IP")
            q: queue.PriorityQueue = queue.PriorityQueue()
            for ip in iter_targets(cfg, self.rng):
                self.seen.add(ip)
                q.put((1, self.rng.random(), ip))
            self.total = len(self.seen)
            if not self.total:
                self.log("No valid IPs to test (check the custom ranges).")
            threads = [threading.Thread(target=self._worker, args=(q,), daemon=True)
                       for _ in range(min(cfg.threads, max(1, self.total)))]
            for t in threads:
                t.start()
            q.join()
            self.phase = "finishing"
            for t in threads:
                t.join(timeout=2)
            if self.soft.is_set():
                self.log(f"Target reached: {len(self.results)} clean IPs.")
            if cfg.speed and self.results and not self.stop.is_set():
                self.phase = "speed"
                best = sorted(self.results, key=lambda r: -r["score"])[: cfg.speed_top]
                self.log(f"Download speed test for the {len(best)} best IPs...")
                for r in best:
                    if self.stop.is_set():
                        break
                    r["speed"] = speed_test(r["ip"], cfg)
            if not self.results and not self.stop.is_set() and self.diag_on_empty:
                self.phase = "diagnosing"
                self.log("No clean IP found; checking why...")
                d = self.diag = diagnose(cfg)
                if d["verdict"] == "ok":
                    top = ", ".join(f"{k}: {v}" for k, v in self.reasons.most_common(3)) or "-"
                    d["advice"] = [f"Connection is fine but none of this random sample passed (top reasons: {top}). "
                                   "Raise the IP count, lower threads to 16 and raise the timeout to 6-8 s."]
                for a in d["advice"]:
                    self.log(a)
            self.phase = "stopped" if self.stop.is_set() else "done"
            self.log(f"Finished: {len(self.results)} clean IPs out of {self.tested} tested.")
        except Exception as e:  # noqa: BLE001
            self.log(f"Scan error: {e}")
            self.phase = "done"
        finally:
            self.finished = time.time()


def best_ips(results: list, n: int) -> list:
    """Best N IPs by score. If the WebSocket test was on, only IPs that passed it are eligible."""
    ws_tested = any(r.get("ws") is not None for r in results)
    pool = [r for r in results if r.get("ws")] if ws_tested else list(results)
    pool.sort(key=lambda r: -r["score"])
    return [r["ip"] for r in pool[: max(1, n)]]


def panel_login(base: str, panel: str, password: str, log, wait: int = 90):
    s = web_session()
    s.headers["User-Agent"] = "Mozilla/5.0 (AminiumStudio)"
    api = f"{base}{panel}/api"
    deadline, last = time.time() + wait, ""
    while True:
        try:
            r = s.post(api + "/login", json={"password": password}, timeout=20)
            if r.status_code == 200 and r.json().get("ok"):
                return s, api
            last = f"HTTP {r.status_code}"
            if r.status_code == 401:
                raise CFError("Panel rejected the admin password")
        except requests.RequestException as e:
            last = str(e)
        except ValueError:
            last = "non-JSON answer"
        if time.time() > deadline:
            raise CFError(f"Panel not reachable ({last})")
        log(f"Waiting for the panel... ({last})")
        time.sleep(5)


def panel_apply_clean(base: str, panel: str, password: str, ips: list, log, keep_domains: bool = True, extra: dict | None = None):
    """Write clean IPs (+ optional extra settings such as tls / ports / protocols) into the panel.
    Existing CDN domains in the list are kept, old IPs are replaced."""
    s, api = panel_login(base, panel, password, log)
    state = s.get(api + "/state", timeout=20).json()
    cur = (state.get("settings") or {}).get("cleanAddrs") or []
    def _is_ip(x):
        try:
            ipaddress.ip_address(str(x).strip().strip("[]"))
            return True
        except ValueError:
            return False
    keep = [x for x in cur if not _is_ip(x)] if keep_domains else []
    new = keep + [ip for ip in ips if ip not in keep]
    body = {"cleanAddrs": new}
    body.update(extra or {})
    if body.get("maxLinks") == 0:      # this panel version rejects 0: send the real number of links we expect instead
        body["maxLinks"] = max(1, len(new) * len(body.get("ports") or TLS_PORTS) * 2)
    r = s.post(api + "/settings", json=body, timeout=30)
    if r.status_code == 422 and "maxLinks" in r.text and "maxLinks" in body:
        log("Panel did not accept maxLinks; retrying without it.")
        body.pop("maxLinks")
        r = s.post(api + "/settings", json=body, timeout=30)
    if r.status_code != 200:
        raise CFError(f"Panel refused the settings (HTTP {r.status_code}): {r.text[:200]}")
    log(f"Panel updated: {len(ips)} clean IPs written (kept {len(keep)} existing domain entries).")
    try:                                   # read the settings back: shows what the panel REALLY stored (ports, limits...)
        st = (s.get(api + "/state", timeout=20).json().get("settings") or {})
        log("Panel now has: " + ", ".join(f"{k}={st.get(k)}" for k in ("tls", "ports", "portsHttp", "protocols", "maxLinks"))
            + f", addresses={len(st.get('cleanAddrs') or [])}")
        want = body.get("ports")
        if want and st.get("ports") != want:
            log(f"WARNING: the panel did not keep the ports we sent ({want}) - it answered {st.get('ports')}.")
    except Exception as e:  # noqa: BLE001
        log(f"Could not read the panel settings back: {e}")


def panel_set(base: str, panel: str, password: str, settings: dict, log):
    s, api = panel_login(base, panel, password, log, wait=30)
    settings = {k: v for k, v in settings.items() if not (k == "maxLinks" and v == 0)}     # this panel rejects maxLinks=0
    r = s.post(api + "/settings", json=settings, timeout=30)
    if r.status_code != 200:
        raise CFError(f"Panel refused the settings (HTTP {r.status_code}): {r.text[:200]}")


def host_of(url: str) -> str:
    return urlparse(url).hostname or ""


# ════════════════════════════════════════════════════════════════════════════
#  PART 4 - delivery helpers (sub formats, raw links, QR)
# ════════════════════════════════════════════════════════════════════════════
FORMATS = [  # key, button label, query, file name (None = no file, link only)
    ("auto", "Auto (recommended)", "", None),
    ("xray", "Xray + fragment", "?format=xray", "xray.json"),
    ("clash", "Clash", "?format=clash", "clash.yaml"),
    ("singbox", "sing-box", "?format=singbox", "singbox.json"),
    ("patt", "Patt", "?format=patt", "patt.txt"),
    ("v2ray", "Plain links", "?format=base64", "sub_v2ray.txt"),
]
RAW = "Raw links (no fragment)"
AUTO_NOTE = ("This is the plain subscription link of your panel. Paste it into v2rayN, v2rayNG, Hiddify, Clash, sing-box ... "
             "and the panel sends each app the format that suits it (Xray apps get the list WITH TLS fragment).")
FORMAT_HELP = {
    "auto": "Best choice. Same kind of link the plain deployer gives you: every app receives the right format by itself.",
    "xray": "For Xray-core apps (v2rayN, v2rayNG...). Includes TLS fragment - the reason many configs connect on filtered networks.",
    "clash": "For Clash / Mihomo / Stash.",
    "singbox": "For sing-box / Hiddify / Karing.",
    "patt": "For PattNG-style clients (extra TLS disguise).",
    "v2ray": "Plain share links WITHOUT fragment. On filtered networks they often do not connect even though the Auto link works.",
    RAW: "Single share links WITHOUT fragment. If they show no ping, use the Auto or Xray link instead.",
}


def links_from_base64(raw: str) -> list:
    raw = (raw or "").strip()
    if not raw:
        return []
    try:
        dec = base64.b64decode(raw + "=" * (-len(raw) % 4)).decode("utf-8", "replace")
    except Exception:
        dec = raw
    return [ln.strip() for ln in dec.splitlines() if re.match(r"^[a-z0-9]+://", ln.strip())]


_LINK_PORT = re.compile(r"^([a-z0-9]+://[^@/?#]+@(?:\[[^\]]+\]|[^:/?#]+)):(\d+)(.*)$", re.I | re.S)


CHOSEN_PORTS: dict = {}      # tls(bool) -> ports picked in the app (empty = all Cloudflare ports)
MAX_LINKS = 0                # 0 = no limit; otherwise the most config links we hand out


def expand_ports(links: list, tls: bool) -> list:
    """The panel may hand out one port per address. Make every link available on ALL Cloudflare ports of its kind
    (TLS: 443 2053 2083 2087 2096 8443 / plain: 80 8080 8880 2052 2082 2086 2095): same address, same SNI/host/path, only the port changes."""
    ports = CHOSEN_PORTS.get(tls) or (TLS_PORTS if tls else PLAIN_PORTS)
    out, seen = [], set()
    for ln in links:
        m = _LINK_PORT.match(ln)
        variants = [ln]
        if m and int(m.group(2)) in ports:
            head, old, tail = m.groups()
            variants = []
            for p in ports:
                t = tail
                if "#" in t:
                    a, _, name = t.partition("#")
                    t = f"{a}#{name.replace(old, str(p)) if old in name else name + '-' + str(p)}"
                variants.append(f"{head}:{p}{t}")
        for v in variants:
            if v not in seen:
                seen.add(v)
                out.append(v)
    return out


def fetch_configs(sub: str, log, tls: bool = True) -> dict:
    """Download every subscription format from the panel and decode the raw vless/trojan links."""
    out = {"sub": sub, "text": {}, "links": []}
    out["text"]["auto"] = AUTO_NOTE
    for key, _, q, _ in FORMATS:
        if key == "auto":
            continue
        try:
            r = web_session().get(sub + q, timeout=30, headers={"User-Agent": "AminiumStudio"})
            if r.status_code == 200:
                out["text"][key] = r.text
            else:
                log(f"{key}: HTTP {r.status_code}")
        except requests.RequestException as e:
            log(f"{key}: {e}")
    raw = links_from_base64(out["text"].get("v2ray", ""))
    out["links"] = expand_ports(raw, tls)
    if MAX_LINKS and len(out["links"]) > MAX_LINKS:
        out["links"] = out["links"][:MAX_LINKS]
    if raw and len(out["links"]) != len(raw):
        out["text"]["v2ray"] = base64.b64encode("\n".join(out["links"]).encode()).decode()      # plain-links file/preview: all ports too
        log(f"Plain links: {len(raw)} from the panel -> {len(out['links'])} on {len(CHOSEN_PORTS.get(tls) or (TLS_PORTS if tls else PLAIN_PORTS))} ports.")
    return out


def qr_matrix(text: str):
    if qrcode is None:
        return None
    qr = qrcode.QRCode(border=2, error_correction=qrcode.constants.ERROR_CORRECT_L)
    qr.add_data(text)
    qr.make(fit=True)
    return qr.get_matrix()


def _write_png_matrix(m, path: str, scale: int = 8) -> None:
    """Write a QR matrix as a PNG with the standard library only (no Pillow needed - works on Android)."""
    import struct
    n = len(m)
    size = n * scale
    raw = bytearray()
    for row in m:
        line = bytearray()
        for v in row:
            line += (b"\x00" if v else b"\xff") * scale
        for _ in range(scale):
            raw += b"\x00" + bytes(line)

    def chunk(tag: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)
    png = (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", size, size, 8, 0, 0, 0, 0))
           + chunk(b"IDAT", zlib.compress(bytes(raw), 9)) + chunk(b"IEND", b""))
    Path(path).write_bytes(png)


def save_qr(text: str, path_no_ext: Path) -> str:
    """PNG when Pillow is present, otherwise SVG. Returns the written file name ('' = no qrcode module)."""
    if qrcode is None:
        return ""
    qr = qrcode.QRCode(border=2, error_correction=qrcode.constants.ERROR_CORRECT_L)
    qr.add_data(text)
    qr.make(fit=True)
    try:
        img = qr.make_image(fill_color="black", back_color="white")
        p = str(path_no_ext) + ".png"
        img.save(p)
        return p
    except Exception:
        try:
            p = str(path_no_ext) + ".png"
            _write_png_matrix(qr.get_matrix(), p)
            return p
        except Exception:
            pass
        import qrcode.image.svg as qsvg  # type: ignore
        img = qr.make_image(image_factory=qsvg.SvgPathImage)
        p = str(path_no_ext) + ".svg"
        img.save(p)
        return p


def save_all(rec: dict, out: dict, log) -> Path:
    folder = OUT_DIR / rec["project"]
    folder.mkdir(parents=True, exist_ok=True)
    urls = []
    for key, label, q, fname in FORMATS:
        txt = out["text"].get(key)
        if txt is None:
            continue
        if fname:
            (folder / fname).write_text(txt, encoding="utf-8")
        url = out["sub"] + q
        urls.append(f"{label}: {url}")
        save_qr(url, folder / f"qr_{key}")
    (folder / "sub_links.txt").write_text("\n".join(urls) + "\n", encoding="utf-8")
    (folder / "links.txt").write_text("\n".join(out["links"]) + "\n", encoding="utf-8")
    (folder / "panel.txt").write_text(
        f"Panel:    {rec['base']}{rec['panel_path']}\nPassword: {rec['password']}\nSub:      {out['sub']}\n", encoding="utf-8")
    log(f"Saved {len(out['links'])} config links, {len(urls)} subscription formats and QR codes to {folder}")
    return folder


# ════════════════════════════════════════════════════════════════════════════
#  PART 5 - look & feel (Kivy / Android)
# ════════════════════════════════════════════════════════════════════════════
import kivy
from kivy.animation import Animation
from kivy.app import App
from kivy.clock import Clock
from kivy.core.clipboard import Clipboard
from kivy.core.window import Window
from kivy.graphics import Color, Ellipse, Line, Rectangle, RoundedRectangle
from kivy.graphics.texture import Texture
from kivy.metrics import dp, sp
from kivy.properties import NumericProperty, StringProperty
from kivy.uix.anchorlayout import AnchorLayout
from kivy.uix.behaviors import ButtonBehavior
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.filechooser import FileChooserListView
from kivy.uix.floatlayout import FloatLayout
from kivy.uix.gridlayout import GridLayout
from kivy.uix.label import Label
from kivy.uix.modalview import ModalView
from kivy.uix.screenmanager import Screen, ScreenManager, SlideTransition
from kivy.uix.scrollview import ScrollView
from kivy.uix.textinput import TextInput
from kivy.uix.widget import Widget
from kivy.utils import escape_markup
from kivy.utils import platform as kplatform

BG, CARD, CARD2, EDGE = "#0a0f1f", "#121a33", "#1b2548", "#2c386b"
TXT, SUB, ACC, ACC2 = "#eef1ff", "#93a0d0", "#6f86ff", "#b36bff"
GOOD, WARN, BAD, SHADOW, FIELD = "#37e3a3", "#ffc35c", "#ff6b86", "#050813", "#0d1430"
ACC_DN = "#5a70e6"
_MONO_PATH = os.path.join(kivy.kivy_data_dir, "fonts", "RobotoMono-Regular.ttf")
MONO = _MONO_PATH if os.path.exists(_MONO_PATH) else "Roboto"

MODE_PAGES = "Pages (pages.dev)"
MODE_WORKERS = "Workers (recommended)"
LOWER = string.ascii_lowercase + string.digits
STEPS = ["Token", "Clean IPs", "Build", "Configs"]
FAMILY = {"IPv4": "v4", "IPv4 + IPv6": "both", "IPv6": "v6"}
FAMILY_HELP = {
    "v4": "Classic Cloudflare IPv4 ranges.",
    "both": "Half IPv4, half IPv6 candidates. IPv6 is skipped automatically if your internet has none.",
    "v6": "IPv6 only - needs a working IPv6 connection (your ISP / router must provide it).",
}
FINGERPRINTS = ["chrome", "firefox", "safari", "ios", "android", "edge", "randomized"]
DEPTH = {  # how hard to look for IPs  ->  more IPs = more configs (configs = IPs x ports x protocols)
    "Quick": dict(count=800, target=120, keep=80, threads=48),
    "Normal": dict(count=2500, target=400, keep=200, threads=64),
    "Deep": dict(count=5000, target=800, keep=400, threads=96),
}
PANEL_STYLE = {"ports": TLS_PORTS, "portsHttp": PLAIN_PORTS, "protocols": {"vless": True, "trojan": True}, "maxLinks": 0}
PER_PAGE = 40          # raw links shown per page (the list can hold thousands)
MAX_ROWS = 100         # best scan results drawn on screen


def _rgb(h):
    h = h.lstrip("#")
    return tuple(int(h[i:i + 2], 16) for i in (0, 2, 4))


def lerp(c1, c2, t):
    a, b = _rgb(c1), _rgb(c2)
    t = max(0.0, min(1.0, t))
    return "#%02x%02x%02x" % tuple(int(a[i] + (b[i] - a[i]) * t) for i in range(3))


def rnd_name() -> str:
    n = rnd(13, LOWER)
    return ("a" + n[1:]) if n[0].isdigit() else n


def C(h, a=1.0):
    """'#rrggbb' -> Kivy rgba tuple."""
    r, g, b = _rgb(h)
    return (r / 255.0, g / 255.0, b / 255.0, a)


def grad_tex(c1, c2, n=96):
    """1-pixel-high horizontal gradient texture (smooth, cheap)."""
    a, b = _rgb(c1), _rgb(c2)
    buf = bytearray()
    for i in range(n):
        f = i / float(n - 1)
        buf += bytes(int(a[k] + (b[k] - a[k]) * f) for k in range(3))
    tex = Texture.create(size=(n, 1), colorfmt="rgb")
    tex.blit_buffer(bytes(buf), colorfmt="rgb", bufferfmt="ubyte")
    tex.mag_filter = "linear"
    tex.min_filter = "linear"
    return tex


class Var:
    """Tiny stand-in for tkinter's StringVar / BooleanVar."""

    def __init__(self, value=None):
        self._v = value
        self._cbs: list = []

    def get(self):
        return self._v

    def set(self, v):
        self._v = v
        for cb in list(self._cbs):
            try:
                cb(v)
            except Exception:  # pragma: no cover
                pass

    def trace(self, cb):
        self._cbs.append(cb)


# ───────────────────────────── basic building blocks ─────────────────────────────
class Panel(BoxLayout):
    """Rounded coloured box with optional border and soft drop shadow."""

    def __init__(self, bg=CARD, radius=14, border=None, shadow=False, auto=False, **kw):
        kw.setdefault("orientation", "vertical")
        super().__init__(**kw)
        self._r = dp(radius)
        self._sh = self._line = self._bcol = None
        with self.canvas.before:
            if shadow:
                Color(*C(SHADOW, 0.6))
                self._sh = RoundedRectangle(radius=[self._r + dp(2)])
            self._col = Color(*C(bg))
            self._rect = RoundedRectangle(radius=[self._r])
            if border:
                self._bcol = Color(*C(border))
                self._line = Line(width=1.0)
        self.bind(pos=self._upd, size=self._upd)
        if auto:
            self.size_hint_y = None
            self.bind(minimum_height=self.setter("height"))
        self._upd()

    def _upd(self, *_):
        x, y = self.pos
        w, h = self.size
        if self._sh is not None:
            self._sh.pos = (x - dp(1), y - dp(5))
            self._sh.size = (w + dp(2), h)
        self._rect.pos = self.pos
        self._rect.size = self.size
        if self._line is not None and w > dp(8) and h > dp(8):
            self._line.rounded_rectangle = (x, y, w, h, self._r)

    def set_bg(self, color_hex):
        self._col.rgba = C(color_hex)

    def set_border(self, color_hex):
        if self._bcol is not None:
            self._bcol.rgba = C(color_hex)


class VBox(BoxLayout):
    """Vertical box that is exactly as tall as its content."""

    def __init__(self, **kw):
        kw.setdefault("orientation", "vertical")
        kw.setdefault("size_hint_y", None)
        super().__init__(**kw)
        self.height = 0
        self.bind(minimum_height=self.setter("height"))


class HBox(BoxLayout):
    """Horizontal box that is exactly as tall as its tallest child."""

    def __init__(self, **kw):
        kw.setdefault("orientation", "horizontal")
        kw.setdefault("size_hint_y", None)
        super().__init__(**kw)
        self.height = 0
        self.bind(minimum_height=self.setter("height"))


class Holder(VBox):
    """A slot whose content can be swapped / emptied (replaces pack / pack_forget)."""


def set_children(box, *widgets):
    box.clear_widgets()
    for w in widgets:
        if w.parent is not None:
            w.parent.remove_widget(w)
        box.add_widget(w)


class Text(Label):
    """Wrapping label that sizes itself to its text."""

    def __init__(self, text="", color=TXT, size=14, bold=False, halign="left", mono=False, **kw):
        kw.setdefault("size_hint_y", None)
        kw.setdefault("height", dp(20))
        super().__init__(text=text, color=C(color), font_size=sp(size), bold=bold, halign=halign, valign="middle", **kw)
        if mono:
            self.font_name = MONO
        self.bind(width=self._wrap, texture_size=self._fit)

    def _wrap(self, *_):
        if self.width > 1:
            self.text_size = (self.width, None)

    def _fit(self, *_):
        self.height = self.texture_size[1] + dp(4)

    def configure(self, text=None, text_color=None, **kw):
        if text is not None:
            self.text = text
        if text_color:
            self.color = C(text_color)


class Btn(ButtonBehavior, Label):
    """Rounded button with press feedback. kind: primary | soft | color | seg"""

    def __init__(self, text="", cmd=None, kind="soft", color=None, hover=None, h=40, size=14, fit=False, radius=11, **kw):
        kw.setdefault("size_hint_y", None)
        super().__init__(text=text, font_size=sp(size), halign="center", valign="middle", **kw)
        self.height = dp(h)
        self.cmd = cmd
        self._radius = dp(radius)
        self._border = kind == "soft"
        self.bold = kind in ("primary", "color")
        if kind == "primary":
            self._n, self._d, txt = ACC, ACC_DN, "#ffffff"
        elif kind == "color":
            self._n, self._d, txt = color or ACC, hover or color or ACC_DN, "#ffffff"
        elif kind == "seg":
            self._n, self._d, txt = CARD2, EDGE, SUB
        else:
            self._n, self._d, txt = CARD2, EDGE, TXT
        self.color = C(txt)
        with self.canvas.before:
            self._c = Color(*C(self._n))
            self._rect = RoundedRectangle(radius=[self._radius])
            self._bc = Color(*C(EDGE, 1.0 if self._border else 0.0))
            self._line = Line(width=1.0)
        self.bind(pos=self._upd, size=self._upd, state=self._on_state)
        if fit:
            self.size_hint_x = None
            self.bind(texture_size=lambda *_: setattr(self, "width", self.texture_size[0] + dp(30)))
        else:
            self.bind(size=lambda *_: setattr(self, "text_size", (max(1, self.width - dp(8)), self.height)))
        self._upd()

    def _upd(self, *_):
        self._rect.pos = self.pos
        self._rect.size = self.size
        x, y = self.pos
        w, h = self.size
        if self._border and w > dp(8) and h > dp(8):
            self._line.rounded_rectangle = (x, y, w, h, self._radius)

    def _on_state(self, *_):
        self._c.rgba = C(self._d if self.state == "down" else self._n)

    def paint(self, n, d, txt):
        self._n, self._d = n, d
        self.color = C(txt)
        self._c.rgba = C(n)

    def on_release(self):
        if self.cmd and not self.disabled:
            self.cmd()

    def configure(self, state=None, text=None, **kw):
        if text is not None:
            self.text = text
        if state is not None:
            off = state == "disabled"
            self.disabled = off
            self.opacity = 0.42 if off else 1.0


def b_primary(text, cmd, **kw):
    kw.setdefault("h", 42)
    return Btn(text, cmd, kind="primary", **kw)


def b_soft(text, cmd, **kw):
    kw.setdefault("h", 40)
    return Btn(text, cmd, kind="soft", **kw)


def b_color(text, cmd, color, hover, **kw):
    kw.setdefault("h", 40)
    return Btn(text, cmd, kind="color", color=color, hover=hover, **kw)


def btn_row(*btns, weights=None):
    row = HBox(spacing=dp(8))
    for i, b in enumerate(btns):
        b.size_hint_x = (weights[i] if weights else 1)
        row.add_widget(b)
    return row


def btn_grid(*btns, cols=2):
    g = GridLayout(cols=cols, spacing=dp(8), size_hint_y=None, row_default_height=dp(40), row_force_default=True)
    g.bind(minimum_height=g.setter("height"))
    for b in btns:
        b.size_hint_x = 1
        g.add_widget(b)
    return g


class Entry(Panel):
    def __init__(self, text="", hint="", password=False, on_change=None, on_blur=None, readonly=False, numeric=False,
                 h=44, **kw):
        super().__init__(bg=FIELD, radius=11, border=EDGE, size_hint_y=None, height=dp(h), **kw)
        self.on_change, self.on_blur = on_change, on_blur
        self.ti = TextInput(
            text=text, hint_text=hint, multiline=False, password=password, readonly=readonly,
            background_normal="", background_active="", background_disabled_normal="", background_color=(0, 0, 0, 0),
            foreground_color=C(TXT), hint_text_color=C("#5d6a99"), cursor_color=C(ACC), selection_color=C(ACC, 0.35),
            font_size=sp(15), write_tab=False, input_type="number" if numeric else "text",
            keyboard_suggestions=not password, size_hint=(1, 1))
        self.add_widget(self.ti)
        self.ti.bind(size=self._pad, focus=self._focus, text=self._chg)
        self._pad()

    def _pad(self, *_):
        py = max(0, (self.ti.height - self.ti.line_height) / 2.0)
        self.ti.padding = [dp(12), py, dp(12), 0]

    def _focus(self, _w, focused):
        self.set_border(ACC if focused else EDGE)
        if not focused and self.on_blur:
            self.on_blur()

    def _chg(self, *_):
        if self.on_change:
            self.on_change()

    def get(self):
        return self.ti.text

    def set(self, v):
        self.ti.text = str(v)

    def configure(self, show=None, **kw):
        if show is not None:
            self.ti.password = show == "*"


class TextBox(Panel):
    """Multi-line text field. Also understands the tiny tk Text API used by the logic (get / delete / insert)."""

    def __init__(self, text="", readonly=False, h=100, mono=True, size=12, **kw):
        super().__init__(bg=FIELD, radius=11, border=EDGE, size_hint_y=None, height=dp(h), **kw)
        self.ti = TextInput(
            text=text, multiline=True, readonly=readonly,
            background_normal="", background_active="", background_disabled_normal="", background_color=(0, 0, 0, 0),
            foreground_color=C(TXT), cursor_color=C(ACC) if not readonly else (0, 0, 0, 0), selection_color=C(ACC, 0.35),
            font_size=sp(size), font_name=MONO if mono else "Roboto", padding=[dp(10), dp(8), dp(10), dp(8)],
            size_hint=(1, 1))
        self.add_widget(self.ti)

    def get(self, *_):
        return self.ti.text

    def set(self, v):
        self.ti.text = str(v)

    def delete(self, *_):
        self.ti.text = ""

    def insert(self, _idx, txt):
        self.ti.text = self.ti.text + str(txt)

    def configure(self, **kw):
        pass

    def to_end(self):
        try:
            self.ti.cursor = self.ti.get_cursor_from_index(len(self.ti.text))
        except Exception:  # pragma: no cover
            pass


class Check(ButtonBehavior, BoxLayout):
    """Check box with a wrapping label."""

    def __init__(self, text, var, command=None, **kw):
        kw.setdefault("size_hint_y", None)
        super().__init__(orientation="horizontal", spacing=dp(10), **kw)
        self.var, self.command = var, command
        a = AnchorLayout(size_hint_x=None, width=dp(28), anchor_x="center", anchor_y="center")
        self.box = Widget(size_hint=(None, None), size=(dp(22), dp(22)))
        a.add_widget(self.box)
        b = AnchorLayout(anchor_x="left", anchor_y="center")
        self.txt = Text(text, color=TXT, size=14)
        b.add_widget(self.txt)
        self.add_widget(a)
        self.add_widget(b)
        self.height = dp(40)
        self.txt.bind(height=lambda *_: setattr(self, "height", max(dp(40), self.txt.height + dp(14))))
        self.box.bind(pos=self._draw, size=self._draw)
        var.trace(lambda v: self._draw())
        self._draw()

    def _draw(self, *_):
        on = bool(self.var.get())
        c = self.box.canvas
        c.clear()
        x, y = self.box.pos
        w, h = self.box.size
        with c:
            Color(*C(ACC if on else FIELD))
            RoundedRectangle(pos=(x, y), size=(w, h), radius=[dp(6)])
            if not on:
                Color(*C(EDGE))
                Line(rounded_rectangle=(x, y, w, h, dp(6)), width=1.2)
            else:
                Color(1, 1, 1, 1)
                Line(points=[x + w * 0.22, y + h * 0.52, x + w * 0.43, y + h * 0.28, x + w * 0.78, y + h * 0.72], width=dp(1.8))

    def on_release(self):
        self.var.set(not self.var.get())
        if self.command:
            self.command()


class Seg(Panel):
    """Segmented control (like CTkSegmentedButton). The command is called only when the user taps."""

    def __init__(self, values, var=None, command=None, scroll=False, size=13, h=44, **kw):
        super().__init__(bg=FIELD, radius=12, border=EDGE, orientation="horizontal", size_hint_y=None, height=dp(h),
                         padding=dp(3), **kw)
        self.values = list(values)
        self.var = var or Var(self.values[0] if self.values else "")
        self.command = command
        self.pills: dict = {}
        self.row = BoxLayout(orientation="horizontal", spacing=dp(3))
        if scroll:
            self.row.size_hint_x = None
            self.row.bind(minimum_width=self.row.setter("width"))
            sv = ScrollView(do_scroll_y=False, bar_width=0, scroll_type=["content"])
            sv.add_widget(self.row)
            self.add_widget(sv)
        else:
            self.add_widget(self.row)
        for v in self.values:
            p = Btn(v, (lambda v=v: self._click(v)), kind="seg", size=size, h=h - 6, fit=scroll, radius=9)
            self.pills[v] = p
            self.row.add_widget(p)
        self.var.trace(lambda v: self._refresh())
        self._refresh()

    def _refresh(self):
        cur = self.var.get()
        for v, p in self.pills.items():
            if v == cur:
                p.paint(ACC, ACC_DN, "#ffffff")
                p.bold = True
            else:
                p.paint(CARD2, EDGE, SUB)
                p.bold = False

    def _click(self, v):
        self.var.set(v)
        if self.command:
            self.command(v)

    def get(self):
        return self.var.get()

    def set(self, v):
        self.var.set(v)


class Pick(ButtonBehavior, Panel):
    """Drop-down (like CTkOptionMenu): tap to choose from a list."""

    def __init__(self, values, command=None, h=44, **kw):
        super().__init__(bg=CARD2, radius=11, border=EDGE, orientation="horizontal", size_hint_y=None, height=dp(h),
                         padding=[dp(12), 0, dp(8), 0], **kw)
        self.values = list(values)
        self.command = command
        self.value = self.values[0] if self.values else ""
        self.lbl = Label(text=self.value, color=C(TXT), font_size=sp(14), halign="left", valign="middle",
                         shorten=True, shorten_from="right")
        self.lbl.bind(size=lambda w, _: setattr(w, "text_size", (w.width, w.height)))
        self.arrow = Widget(size_hint_x=None, width=dp(26))
        self.arrow.bind(pos=self._chev, size=self._chev)
        self.add_widget(self.lbl)
        self.add_widget(self.arrow)

    def _chev(self, *_):
        c = self.arrow.canvas
        c.clear()
        cx, cy = self.arrow.center
        with c:
            Color(*C(SUB))
            Line(points=[cx - dp(5), cy + dp(2), cx, cy - dp(3), cx + dp(5), cy + dp(2)], width=dp(1.6))

    def get(self):
        return self.value

    def set(self, v):
        self.value = v
        self.lbl.text = str(v)

    def configure(self, values=None, **kw):
        if values is not None:
            self.values = list(values)

    def on_release(self):
        if not self.values:
            return
        mv = ModalView(size_hint=(0.88, None), height=dp(100), background="", background_color=(0, 0, 0, 0),
                       overlay_color=(0, 0, 0, 0.65), auto_dismiss=True)
        box = Panel(bg=CARD, radius=16, border=EDGE, padding=dp(10), spacing=dp(6))
        sv = ScrollView(do_scroll_x=False, bar_width=dp(3))
        lst = VBox(spacing=dp(6))

        def choose(v):
            self.set(v)
            mv.dismiss()
            if self.command:
                self.command(v)
        for v in self.values:
            lst.add_widget(Btn(v, (lambda v=v: choose(v)), kind="primary" if v == self.value else "soft", h=44))
        sv.add_widget(lst)
        box.add_widget(sv)
        mv.height = min(Window.height * 0.7, len(self.values) * dp(50) + dp(24))
        mv.add_widget(box)
        mv.open()


class Bar(Widget):
    """Smooth progress bar."""
    value = NumericProperty(0.0)

    def __init__(self, **kw):
        kw.setdefault("size_hint_y", None)
        kw.setdefault("height", dp(8))
        super().__init__(**kw)
        with self.canvas:
            Color(*C(CARD2))
            self._tr = RoundedRectangle(radius=[dp(4)])
            Color(*C(ACC))
            self._fr = RoundedRectangle(radius=[dp(4)])
        self.bind(pos=self._u, size=self._u, value=self._u)
        self._u()

    def _u(self, *_):
        self._tr.pos, self._tr.size = self.pos, self.size
        self._fr.pos = self.pos
        self._fr.size = (max(0.0, self.width * self.value), self.height)

    def set(self, v):
        v = max(0.0, min(1.0, float(v)))
        Animation.cancel_all(self, "value")
        Animation(value=v, d=0.25, t="out_quad").start(self)


class Banner(FloatLayout):
    """Gradient header strip."""

    def __init__(self, **kw):
        kw.setdefault("size_hint_y", None)
        kw.setdefault("height", dp(84))
        super().__init__(**kw)
        try:
            self.tex = grad_tex("#1b2b7d", "#5b2fb3")
        except Exception:  # pragma: no cover
            self.tex = None
        self.title = Label(text="AMINIUM STUDIO", bold=True, font_size=sp(23), color=(1, 1, 1, 1), halign="left",
                           valign="middle", size_hint=(None, None))
        self.sub = Label(text="token  >  clean IPs  >  build  >  configs & QR", font_size=sp(12), color=C("#cdd5ff"),
                         halign="left", valign="middle", size_hint=(None, None))
        self.tag = Label(text="IPv4  \u2022  IPv6", bold=True, font_size=sp(11), color=C("#e6dcff"), halign="right",
                         valign="middle", size_hint=(None, None))
        for w in (self.title, self.sub, self.tag):
            self.add_widget(w)
        self.bind(pos=self.draw, size=self.draw)
        self.draw()

    def draw(self, *_):
        x, y = self.pos
        w, h = self.size
        self.title.size = (w - dp(36), dp(32))
        self.title.text_size = self.title.size
        self.title.pos = (x + dp(18), y + h * 0.46)
        self.sub.size = (w - dp(36), dp(20))
        self.sub.text_size = self.sub.size
        self.sub.pos = (x + dp(18), y + h * 0.16)
        self.tag.size = (dp(110), dp(20))
        self.tag.text_size = self.tag.size
        self.tag.pos = (x + w - dp(124), y + h - dp(26))
        cv = self.canvas.before
        cv.clear()
        with cv:
            Color(1, 1, 1, 1)
            if self.tex is not None:
                Rectangle(texture=self.tex, pos=self.pos, size=self.size)
            else:
                Color(*C("#2a2f96"))
                Rectangle(pos=self.pos, size=self.size)
            for cx, cy, r, col in ((w - dp(50), y + h - dp(8), dp(44), "#7a55d8"), (w - dp(120), y + dp(10), dp(28), "#5a6fe0"),
                                   (w - dp(14), y + dp(12), dp(20), "#9a6bec")):
                Color(*C(col, 0.55))
                Line(circle=(x + cx, cy, r), width=dp(1.4))
            Color(*C(ACC2))
            Rectangle(pos=(x, y), size=(w, dp(2)))


class StepItem(FloatLayout):
    pulse = NumericProperty(0.0)

    def __init__(self, idx, label, n, on_click, **kw):
        super().__init__(**kw)
        self.idx, self.n, self.cur, self.on_click = idx, n, 0, on_click
        self.anim = None
        self.num = Label(text=str(idx + 1), bold=True, font_size=sp(14), size_hint=(None, None), size=(dp(36), dp(36)))
        self.cap = Label(text=label, font_size=sp(12), size_hint=(None, None), height=dp(18), halign="center", valign="middle")
        self.add_widget(self.num)
        self.add_widget(self.cap)
        self.bind(pos=self.draw, size=self.draw, pulse=self.draw)

    def set_cur(self, cur):
        self.cur = cur
        if self.anim is not None:
            self.anim.cancel(self)
            self.anim = None
        self.pulse = 0.0
        if self.idx == cur:
            self.anim = Animation(pulse=1.0, d=0.9, t="in_out_sine") + Animation(pulse=0.0, d=0.9, t="in_out_sine")
            self.anim.repeat = True
            self.anim.start(self)
        self.draw()

    def draw(self, *_):
        x, y = self.pos
        w, h = self.size
        if w < 4 or h < 4:
            return
        r = dp(17)
        cx, cy = x + w / 2.0, y + h - dp(26)
        self.num.center = (cx, cy)
        self.cap.width = w
        self.cap.text_size = (w, dp(18))
        self.cap.pos = (x, cy - dp(46))
        i, cur = self.idx, self.cur
        self.num.text = str(i + 1)
        self.num.color = C("#ffffff") if i == cur else C(SUB)
        self.num.opacity = 0.0 if i < cur else 1.0
        self.cap.color = C(TXT) if i == cur else C(SUB)
        self.cap.bold = i == cur
        cv = self.canvas.before
        cv.clear()
        with cv:
            gap = r + dp(4)
            if i > 0:
                Color(*C(GOOD if i <= cur else EDGE))
                Line(points=[x, cy, cx - gap, cy], width=dp(1.6))
            if i < self.n - 1:
                Color(*C(GOOD if i < cur else EDGE))
                Line(points=[cx + gap, cy, x + w, cy], width=dp(1.6))
            if i == cur:
                g = dp(3) + dp(5) * self.pulse
                Color(*C(ACC, 0.55 * (1.0 - self.pulse) + 0.1))
                Line(circle=(cx, cy, r + g), width=dp(1.6))
                Color(*C(ACC))
                Ellipse(pos=(cx - r, cy - r), size=(2 * r, 2 * r))
                Color(*C(ACC2))
                Line(circle=(cx, cy, r), width=dp(1.4))
            elif i < cur:
                Color(*C(GOOD))
                Ellipse(pos=(cx - r, cy - r), size=(2 * r, 2 * r))
                Color(*C("#06281a"))
                Line(points=[cx - r * 0.38, cy, cx - r * 0.08, cy - r * 0.32, cx + r * 0.42, cy + r * 0.34], width=dp(2))
            else:
                Color(*C(CARD2))
                Ellipse(pos=(cx - r, cy - r), size=(2 * r, 2 * r))
                Color(*C(EDGE))
                Line(circle=(cx, cy, r), width=dp(1.4))

    def on_touch_down(self, touch):
        if self.collide_point(*touch.pos) and self.idx < self.cur and self.on_click:
            self.on_click(self.idx)
            return True
        return super().on_touch_down(touch)


class Stepper(BoxLayout):
    def __init__(self, labels, on_click, **kw):
        kw.setdefault("size_hint_y", None)
        kw.setdefault("height", dp(76))
        super().__init__(orientation="horizontal", padding=[dp(6), dp(4)], **kw)
        self.cur = 0
        self._started = False
        self.items = [StepItem(i, t, len(labels), on_click) for i, t in enumerate(labels)]
        for it in self.items:
            self.add_widget(it)
        self.set(0)

    def set(self, cur):
        if self._started and cur == self.cur:
            return
        self._started = True
        self.cur = cur
        for it in self.items:
            it.set_cur(cur)


class Disc(FloatLayout):
    """A tilted radar slab. Every clean IP becomes a glowing pillar standing on the disc (height = score)."""
    caption = StringProperty("")

    def __init__(self, **kw):
        kw.setdefault("size_hint_y", None)
        kw.setdefault("height", dp(210))
        super().__init__(**kw)
        self.mode, self.angle, self.blips = "idle", 0.0, []
        self.cap = Label(text="", font_size=sp(12), color=C(SUB), size_hint=(1, None), height=dp(20))
        self.add_widget(self.cap)
        self.bind(pos=self.draw, size=self.draw)
        Clock.schedule_interval(self.tick, 0.05)
        self.draw()

    def on_caption(self, _w, v):
        self.cap.text = v

    def set_blips(self, rows):
        out = []
        for ip, score in rows[:400]:
            h = int(hashlib.md5(ip.encode()).hexdigest()[:8], 16)
            out.append((h % 360, 0.22 + ((h // 360) % 72) / 100.0, score))
        out.sort(key=lambda b: math.sin(math.radians(b[0])) * b[1])     # back to front, once
        self.blips = out

    def draw(self, *_):
        try:
            self._draw()
        except Exception:  # pragma: no cover  (a visual must never crash the app)
            pass

    def _draw(self):
        w, h = self.size
        if w < dp(40) or h < dp(40):
            return
        self.cap.pos = (self.x, self.y + dp(2))
        s = min(w * 0.46 / 168.0, (h - dp(28)) / 190.0)
        rx, ry = 168.0 * s, 64.0 * s
        cx = self.x + w / 2.0
        cy = self.y + dp(24) + 12.0 * s + ry
        cv = self.canvas.before
        cv.clear()

        def pt(ang, frac):
            a = math.radians(ang)
            return cx + math.cos(a) * rx * frac, cy - math.sin(a) * ry * frac
        with cv:
            for d in range(12, 0, -1):                                   # slab thickness
                Color(*C(lerp(EDGE, SHADOW, d / 12.0)))
                Ellipse(pos=(cx - rx, cy - ry - d * s), size=(2 * rx, 2 * ry))
            Color(*C("#0b1230"))
            Ellipse(pos=(cx - rx, cy - ry), size=(2 * rx, 2 * ry))
            Color(*C(ACC))
            Line(ellipse=(cx - rx, cy - ry, 2 * rx, 2 * ry), width=dp(1.5))
            for k in range(14):                                          # soft radial glow
                f = 0.97 - k * 0.07
                Color(*C(lerp("#0b1230", "#1a2a62", k / 14.0)))
                Ellipse(pos=(cx - rx * f, cy - ry * f), size=(2 * rx * f, 2 * ry * f))
            Color(*C("#26336f"))
            for f in (0.75, 0.5, 0.25):
                Line(ellipse=(cx - rx * f, cy - ry * f, 2 * rx * f, 2 * ry * f), width=1.0)
            Color(*C("#1d2858"))
            Line(points=[cx - rx, cy, cx + rx, cy], width=1.0)
            Line(points=[cx, cy - ry, cx, cy + ry], width=1.0)
            if self.mode != "idle":                                      # fading sweep
                head = ACC2 if self.mode == "build" else ACC
                for i in range(16):
                    start = (self.angle - (i + 1) * 3.5 + 90.0) % 360.0
                    Color(*C(lerp(head, "#0b1230", i / 16.0)))
                    Ellipse(pos=(cx - rx, cy - ry), size=(2 * rx, 2 * ry), angle_start=start, angle_end=start + 3.6)
            for ang, fr, score in self.blips:
                x, y = pt(ang, fr)
                hgt = (8 + max(0, min(100, score)) * 0.42) * s
                Color(*C("#0d3a2a"))
                Ellipse(pos=(x - 4 * s, y - 2 * s), size=(8 * s, 4 * s))
                Color(*C(GOOD))
                Line(points=[x, y, x, y + hgt], width=dp(1.3))
                Color(*C("#b8ffe0"))
                Ellipse(pos=(x - 3 * s, y + hgt - 3 * s), size=(6 * s, 6 * s))

    def tick(self, _dt):
        if self.mode != "idle":
            self.angle = (self.angle + (9 if self.mode == "build" else 6)) % 360
            self.draw()


class QRView(Widget):
    """White card that shows a QR matrix (one crisp texture, so even dense codes stay fast)."""

    def __init__(self, **kw):
        kw.setdefault("size_hint", (None, None))
        super().__init__(**kw)
        self.matrix = None
        self.tex = None
        self.bind(pos=self.draw, size=self.draw)

    def set_matrix(self, m):
        self.matrix = m
        self.tex = None
        if m:
            try:
                n = len(m)
                buf = bytearray()
                for row in reversed(m):                    # texture rows run bottom -> top
                    for v in row:
                        buf += b"\x00\x00\x00" if v else b"\xff\xff\xff"
                self.tex = Texture.create(size=(n, n), colorfmt="rgb")
                self.tex.blit_buffer(bytes(buf), colorfmt="rgb", bufferfmt="ubyte")
                self.tex.mag_filter = "nearest"
                self.tex.min_filter = "nearest"
            except Exception:  # pragma: no cover
                self.tex = None
        self.draw()

    def cell_px(self):
        if not self.matrix:
            return 0
        return int((min(self.width, self.height) - dp(24)) // len(self.matrix))

    def draw(self, *_):
        self.canvas.clear()
        with self.canvas:
            Color(1, 1, 1, 1)
            RoundedRectangle(pos=self.pos, size=self.size, radius=[dp(14)])
            if self.matrix and self.tex is not None:
                n = len(self.matrix)
                side = min(self.width, self.height) - dp(24)
                cell = max(1, int(side // n))
                qs = cell * n
                Color(1, 1, 1, 1)
                Rectangle(texture=self.tex, pos=(self.x + (self.width - qs) / 2.0, self.y + (self.height - qs) / 2.0), size=(qs, qs))


class ResRow(Panel):
    """One scan result (two lines, colour = score level)."""

    def __init__(self, r, n, **kw):
        lv = "hi" if r["score"] >= 70 else ("mid" if r["score"] >= 40 else "lo")
        ipc = {"hi": "#c9ffe6", "mid": TXT, "lo": "#e0b872"}[lv]
        scc = {"hi": GOOD, "mid": ACC, "lo": WARN}[lv]
        sp_ = "-" if r["speed"] is None else r["speed"]
        super().__init__(bg=CARD if n % 2 == 0 else "#0f1631", radius=10, size_hint_y=None, height=dp(56),
                         padding=[dp(12), dp(5)], **kw)
        top = ("[b][color=%s]%s[/color][/b]   [color=%s]%s[/color]   [b][color=%s]score %s[/color][/b]"
               % (ipc, escape_markup(str(r["ip"])), SUB, escape_markup(str(r["colo"])), scc, r["score"]))
        low = ("[color=%s]total %s ms  \u2022  tcp %s  tls %s  ttfb %s  \u2022  jitter %s  loss %s%%  \u2022  %s Mbps[/color]"
               % (SUB, r["total"], r["tcp"], r["tls"], r["ttfb"], r["jitter"], r["loss"], sp_))
        for t, size in ((top, 14), (low, 10)):
            lb = Label(text=t, markup=True, font_size=sp(size), halign="left", valign="middle", shorten=True,
                       shorten_from="right")
            lb.bind(size=lambda w, _: setattr(w, "text_size", (w.width, w.height)))
            self.add_widget(lb)


class LinkRow(ButtonBehavior, Label):
    """One raw share link (tap to select)."""

    def __init__(self, link, cmd, selected=False, **kw):
        super().__init__(text=link, font_name=MONO, font_size=sp(11), color=C(TXT), halign="left", valign="middle",
                         shorten=True, shorten_from="right", size_hint_y=None, height=dp(36), **kw)
        self.link, self.cmd, self.selected = link, cmd, selected
        with self.canvas.before:
            self._c = Color(*C(FIELD))
            self._r = RoundedRectangle(radius=[dp(8)])
        self.bind(pos=self._upd, size=self._upd)
        self._upd()
        self.set_selected(selected)

    def _upd(self, *_):
        self._r.pos, self._r.size = self.pos, self.size
        self.text_size = (max(1, self.width - dp(20)), self.height)

    def set_selected(self, on):
        self.selected = on
        self._c.rgba = C(ACC if on else FIELD)

    def on_release(self):
        self.cmd(self.link)


def raised(parent, title=None):
    """A floating card (soft shadow + thin border). Returns the card; add content with card.add_widget(...)."""
    card = Panel(bg=CARD, radius=18, border=EDGE, shadow=True, auto=True, padding=[dp(14), dp(12), dp(14), dp(14)], spacing=dp(9))
    if title:
        hd = HBox(spacing=dp(10))
        bar_slot = AnchorLayout(size_hint=(None, None), size=(dp(4), dp(26)), anchor_y="center")
        bar = Widget(size_hint=(None, None), size=(dp(4), dp(20)))
        with bar.canvas:
            Color(*C(ACC))
            rr = RoundedRectangle(radius=[dp(2)])
        bar.bind(pos=lambda w, p: setattr(rr, "pos", p), size=lambda w, s: setattr(rr, "size", s))
        bar_slot.add_widget(bar)
        t = Text(title, color=TXT, size=16, bold=True, size_hint_x=1)
        hd.add_widget(bar_slot)
        hd.add_widget(t)
        card.add_widget(hd)
    parent.add_widget(card)
    return card


# ════════════════════════════════════════════════════════════════════════════
#  PART 6 - the wizard
# ════════════════════════════════════════════════════════════════════════════
class Wizard(BoxLayout):
    def __init__(self, **kw):
        super().__init__(orientation="vertical", **kw)
        self.cfg = self.load_cfg()
        self.token = self.cfg.get("token", "")
        self.email = self.cfg.get("email", "")
        self.token_ok = False
        self.accounts: list = []
        self.deployments: list = list(self.cfg.get("deployments", []))
        self.busy = False
        self.job: ScanJob | None = None
        self.ips: list = []
        self.pool: list = []
        self.out: dict | None = None
        self.rec: dict | None = None
        self.step = 0
        self.shown_found = -1
        self.cur_fmt = "v2ray"
        self.log_open = False
        self.modal_open = 0
        self.raw_page = 0
        self.sel_link = ""
        self._res_stamp = 0.0
        self.build_ui()
        set_net_log(self.log)
        self.fill_from_cfg()
        self.apply_ports()
        self.roll_all()                       # every launch: new random name / password / paths / UUID (hidden from the user)
        self.log("New random name, password, paths and UUID generated for this launch; every scan draws fresh random IPv4/IPv6 addresses.")
        self.refresh_token_view()
        if self.token:
            self.verify_token(silent=True)
        self.goto(0)
        Window.bind(on_keyboard=self._on_key)

    # ---------------------------------------------------------------- config
    def load_cfg(self) -> dict:
        try:
            return json.loads(CFG_FILE.read_text(encoding="utf-8"))
        except Exception:
            return {}

    def save_cfg(self):
        sf = {k: v for k, v in self.scan_form().items() if k not in ("host", "ws", "ws_path", "count", "target", "threads")}
        data = {
            "token": self.token, "email": self.email, "account_id": self.selected_account_id() or self.cfg.get("account_id", ""),
            "conn": self.v_conn.get(), "depth": self.v_depth.get(), "mode": self.v_mode.get(), "use_d1": bool(self.v_d1.get()),
            "source": self.e_source.get().strip(), "custom_domain": self.e_domain.get().strip(), "decoy": self.e_decoy.get().strip(),
            "proxy": self.e_proxy.get().strip(), "tg_token": self.e_tgtoken.get().strip(), "tg_secret": self.e_tgsecret.get().strip(),
            "tg_admins": self.e_tgadmins.get().strip(), "verify_ws": bool(self.v_verify_ws.get()),
            "remark": self.e_remark.get().strip(), "max_cfg": self.e_maxcfg.get().strip(), "ports_tls": self.chosen_ports(True), "ports_plain": self.chosen_ports(False), "scan": sf, "deployments": self.deployments,
        }
        try:
            CFG_FILE.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
            try:
                os.chmod(CFG_FILE, 0o600)
            except Exception:
                pass
        except Exception as e:
            self.log(f"Could not save config: {e}")

    def shutdown(self):
        if self.job:
            self.job.stop.set()
        try:
            self.save_cfg()
        except Exception:  # pragma: no cover
            pass

    def _on_key(self, _win, key, *_a):
        """Android back button: go one wizard step back (and let the system close the app on step 1)."""
        if key == 27 and self.modal_open <= 0 and self.step > 0 and not self.busy:
            self.goto(self.step - 1)
            return True
        return False

    # ---------------------------------------------------------------- helpers
    def after(self, ms, fn):
        Clock.schedule_once(lambda dt: fn(), ms / 1000.0)

    def row(self, parent, label, show=None, width=None, placeholder="", lw=None, on_change=None, on_blur=None, numeric=False):
        box = VBox(spacing=dp(4))
        box.add_widget(Text(label, color=SUB, size=12))
        e = Entry(hint=placeholder, password=(show == "*"), on_change=on_change, on_blur=on_blur, numeric=numeric)
        box.add_widget(e)
        parent.add_widget(box)
        return e, box

    def field(self, parent, label, widget):
        box = VBox(spacing=dp(4))
        box.add_widget(Text(label, color=SUB, size=12))
        box.add_widget(widget)
        parent.add_widget(box)
        return widget

    def note(self, parent, text, color=SUB, wrap=None):
        lb = Text(text, color=color, size=12)
        parent.add_widget(lb)
        return lb

    @staticmethod
    def set_entry(e, v):
        e.set(v)

    def log(self, msg):
        line = time.strftime("[%H:%M:%S] ") + str(msg)

        def _do(_dt=None):
            self._log_lines.append(line)
            if len(self._log_lines) > 400:
                del self._log_lines[:100]
            self.logbox.ti.text = "\n".join(self._log_lines)
            self.logbox.to_end()
            if str(msg).startswith("ERROR") and not self.log_open:
                self.toggle_log()
        Clock.schedule_once(_do, 0)

    def stage(self, text, frac=None):
        def _do():
            self.lbl_stage.configure(text=text)
            if frac is not None:
                self.progress.set(frac)
        self.after(0, _do)

    def set_progress(self, v):
        self.after(0, lambda: self.progress.set(v))

    def open_url(self, url):
        try:
            if kplatform == "android":
                from jnius import autoclass  # type: ignore
                Intent = autoclass("android.content.Intent")
                Uri = autoclass("android.net.Uri")
                act = autoclass("org.kivy.android.PythonActivity").mActivity
                act.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url)))
            else:
                webbrowser.open(url)
        except Exception as e:
            self.log(f"Could not open browser: {e}")

    def copy_text(self, t, what="Copied."):
        try:
            Clipboard.copy(t)
        except Exception as e:
            self.log(f"Could not copy: {e}")
            return
        self.log(what)

    def toggle_log(self):
        self.log_open = not self.log_open
        if self.log_open:
            set_children(self.log_slot, self.logbox)
            self.btn_log.configure(text="Hide log")
        else:
            self.log_slot.clear_widgets()
            self.btn_log.configure(text="Show log")

    def modal(self, build, width=0.9):
        """Small dialog; build(box, close) fills it."""
        mv = ModalView(size_hint=(width, None), height=dp(200), background="", background_color=(0, 0, 0, 0),
                       overlay_color=(0, 0, 0, 0.65), auto_dismiss=True)
        box = Panel(bg=CARD, radius=16, border=EDGE, auto=True, padding=dp(16), spacing=dp(10))
        box.size_hint_y = None
        box.bind(height=lambda w, h: setattr(mv, "height", min(h, Window.height * 0.9)))
        self.modal_open += 1
        mv.bind(on_dismiss=lambda *_: setattr(self, "modal_open", max(0, self.modal_open - 1)))
        build(box, mv.dismiss)
        mv.add_widget(box)
        mv.open()
        return mv

    def info(self, title, text):
        def build(box, close):
            box.add_widget(Text(title, size=16, bold=True))
            box.add_widget(Text(text, color=SUB, size=13))
            box.add_widget(Btn("OK", close, kind="primary", h=42))
        self.modal(build)

    # ---------------------------------------------------------------- shell
    def build_ui(self):
        with self.canvas.before:
            Color(*C(BG))
            self._bgr = Rectangle(pos=self.pos, size=self.size)
        self.bind(pos=lambda *_: setattr(self._bgr, "pos", self.pos), size=lambda *_: setattr(self._bgr, "size", self.size))
        self._log_lines: list = []
        self.add_widget(Banner())
        self.stepper = Stepper(STEPS, lambda i: (not self.busy) and self.goto(i))
        self.add_widget(self.stepper)
        self.sm = ScreenManager(transition=SlideTransition(duration=0.22))
        self.pages = []
        for i in range(len(STEPS)):
            scr = Screen(name=str(i))
            sv = ScrollView(do_scroll_x=False, bar_width=dp(3), bar_color=C(ACC, 0.7), bar_inactive_color=C(ACC, 0.25),
                            scroll_type=["bars", "content"])
            body = VBox(padding=[dp(12), dp(6), dp(12), dp(24)], spacing=dp(12))
            sv.add_widget(body)
            scr.add_widget(sv)
            self.sm.add_widget(scr)
            self.pages.append(body)
        self.add_widget(self.sm)
        self.build_step_token(self.pages[0])
        self.build_step_scan(self.pages[1])
        self.build_step_build(self.pages[2])
        self.build_step_out(self.pages[3])
        pb = BoxLayout(size_hint_y=None, height=dp(14), padding=[dp(14), dp(3)])
        self.progress = Bar(size_hint_y=1)
        pb.add_widget(self.progress)
        self.add_widget(pb)
        self.log_slot = Holder()
        self.logbox = TextBox(readonly=True, h=150, size=11)
        self.add_widget(self.log_slot)
        nav = BoxLayout(size_hint_y=None, height=dp(62), padding=[dp(12), dp(9)], spacing=dp(10))
        self.btn_back = b_soft("Back", lambda: self.goto(self.step - 1), h=44)
        self.btn_back.size_hint_x = 0.8
        self.btn_log = b_soft("Show log", self.toggle_log, h=44)
        self.btn_log.size_hint_x = 0.9
        self.btn_next = b_primary("Next", self.on_next, h=44)
        self.btn_next.size_hint_x = 1.3
        for b in (self.btn_back, self.btn_log, self.btn_next):
            nav.add_widget(b)
        self.add_widget(nav)

    def gate(self) -> bool:
        if self.busy:
            return False
        if self.step == 0:
            return self.token_ok
        if self.step == 1:
            scanning = bool(self.job and self.job.phase in ("diagnosing", "scanning", "speed", "finishing"))
            return bool(self.job and self.job.snapshot()["results"]) and not scanning
        if self.step == 2:
            return self.out is not None
        return False

    def update_nav(self):
        self.btn_back.configure(state="normal" if self.step > 0 and not self.busy else "disabled")
        if self.step == len(STEPS) - 1:
            self.btn_next.configure(state="disabled", text="All done")
        else:
            self.btn_next.configure(state="normal" if self.gate() else "disabled", text="Next")
        self.stepper.set(self.step)
        working = self.busy or bool(self.job and self.job.phase in ("diagnosing", "scanning", "speed", "finishing"))
        try:
            Window.allow_screensaver = not working          # keep the screen on while a scan / build runs
        except Exception:  # pragma: no cover
            pass

    def goto(self, i):
        i = max(0, min(len(STEPS) - 1, i))
        self.sm.transition.direction = "left" if i > self.step else "right"
        self.step = i
        self.sm.current = str(i)
        if i == 2:
            self.refresh_build_summary()
        if i == 3:
            self.render_output()
        self.update_nav()

    def on_next(self):
        if not self.gate():
            return
        if self.step == 1:
            res = self.job.snapshot()["results"]
            self.ips = best_ips(res, self.keep_count())
            self.pool = best_ips(res, max(self.keep_count() * 3, 150))      # more candidates than we keep: many fail on the worker's own domain
            self.save_cfg()
        self.goto(self.step + 1)

    # ================================================================ 1 - token
    def build_step_token(self, page):
        c = raised(page, "Connect your Cloudflare account")
        self.lbl_tok = Text("", color=TXT, size=14)
        c.add_widget(self.lbl_tok)
        self.slot_tok = Holder(spacing=dp(9))
        c.add_widget(self.slot_tok)
        self.edit_box = VBox(spacing=dp(9))
        self.edit_box.add_widget(btn_row(b_primary("Create token (pre-filled page)", lambda: self.open_url(token_template_url()), h=42),
                                         b_soft("Plain page", lambda: self.open_url(TOKEN_URL), h=42), weights=[1.7, 1]))
        self.note(self.edit_box, "Account permissions: Pages: Edit - Workers KV Storage: Edit - D1: Edit - Workers Scripts: Edit - "
                                 "Account Settings: Read - Account Analytics: Read. (Custom domain: also Zone: Read + DNS: Edit.)")
        self.e_token, _ = self.row(self.edit_box, "API Token / Global Key", show="*", on_change=self.detect_key_type)
        self.email_slot = Holder()
        self.edit_box.add_widget(self.email_slot)
        self.e_email, self.email_row = self.row(self.email_slot, "Email (Global Key only)", placeholder="your Cloudflare login email")
        self.email_slot.clear_widgets()
        self.v_show = Var(False)
        self.btn_cancel_edit = b_soft("Cancel", self.refresh_token_view, h=40)
        self.edit_box.add_widget(Check("Show token", self.v_show, command=lambda: self.e_token.configure(show="" if self.v_show.get() else "*")))
        self.edit_box.add_widget(btn_row(b_primary("Save & verify", self.on_save_token, h=42), self.btn_cancel_edit))
        self.saved_box = VBox(spacing=dp(8))
        self.saved_box.add_widget(btn_row(b_soft("Change token", self.on_change_token), b_soft("Verify again", lambda: self.verify_token(False))))
        self.saved_box.add_widget(b_color("Forget token", self.on_forget_token, "#6a2434", "#8a3045"))
        self.cb_account = Pick(["(verify token first)"])
        self.field(c, "Account", self.cb_account)
        self.lbl_tok_state = Text("", color=SUB, size=13)
        c.add_widget(self.lbl_tok_state)
        self.note(c, "You enter the token once. It is stored privately on this phone (inside the app); press 'Forget token' to remove it.")

    def detect_key_type(self):
        key = self.e_token.get().strip()
        is_global = bool(re.fullmatch(r"[0-9a-fA-F]{37}", key))
        shown = self.email_row.parent is not None
        if is_global and not shown:
            self.email_slot.add_widget(self.email_row)
            self.log("Looks like a Global API Key: enter your Cloudflare email too.")
        elif not is_global and shown:
            self.email_slot.clear_widgets()
            self.set_entry(self.e_email, "")

    def refresh_token_view(self):
        if self.token:
            kind = "Global Key" if self.email else "API Token"
            self.lbl_tok.configure(text=f"{kind} saved:  {self.token[:6]}\u2026{self.token[-4:]}")
            set_children(self.slot_tok, self.saved_box)
        else:
            self.lbl_tok.configure(text="Paste your API token below (only needed once).")
            set_children(self.slot_tok, self.edit_box)
            self.btn_cancel_edit.configure(state="disabled")

    def on_change_token(self):
        self.set_entry(self.e_token, "")
        set_children(self.slot_tok, self.edit_box)
        self.btn_cancel_edit.configure(state="normal")

    def on_forget_token(self):
        self.token, self.email, self.token_ok = "", "", False
        self.accounts = []
        self.cb_account.configure(values=["(verify token first)"])
        self.cb_account.set("(verify token first)")
        self.lbl_tok_state.configure(text="")
        self.save_cfg()
        self.refresh_token_view()
        self.update_nav()
        self.log("Token removed from this PC.")

    def on_save_token(self):
        tok = self.e_token.get().strip()
        if not tok:
            return self.log("Paste the API token first.")
        old = (self.token, self.email)

        def revert():
            self.token, self.email = old
        self.token, self.email = tok, self.e_email.get().strip()
        self.verify_token(False, on_fail=revert)

    def verify_token(self, silent=False, on_fail=None):
        token, email = self.token, self.email
        if not token:
            return
        self.lbl_tok_state.configure(text="Checking the token...", text_color=SUB)

        def work():
            try:
                cf = CF(token, self.log, email)
                info = cf.verify()
                accs = cf.accounts()
                if not accs:
                    raise CFError("No account visible to this token (add 'Account Settings: Read').")
                self.accounts = accs
                vals = [f"{a['name']} ({a['id'][:6]})" for a in accs]
                keep = self.cfg.get("account_id")
                pick = next((v for a, v in zip(accs, vals) if a["id"] == keep), vals[0])

                def ui():
                    self.cb_account.configure(values=vals)
                    self.cb_account.set(pick)
                    self.token_ok = True
                    self.lbl_tok_state.configure(text=f"Token is valid ({info.get('status')}). Press Next.", text_color=GOOD)
                    self.save_cfg()
                    self.refresh_token_view()
                    self.update_nav()
                self.after(0, ui)
            except Exception as e:
                self.log(f"Token check failed: {e}")

                def ui2():
                    self.token_ok = False
                    self.lbl_tok_state.configure(text=f"Token check failed: {e}", text_color=BAD)
                    self.update_nav()
                self.after(0, ui2)
                if on_fail:
                    on_fail()
        threading.Thread(target=work, daemon=True).start()

    def selected_account_id(self):
        sel = self.cb_account.get()
        for a in self.accounts:
            if sel.startswith(a["name"]) and sel.endswith(a["id"][:6] + ")"):
                return a["id"]
        return self.accounts[0]["id"] if self.accounts else None

    # ================================================================ 2 - clean IPs
    def build_step_scan(self, page):
        c = raised(page, "Find clean Cloudflare IPs")
        self.note(c, "Run this on the same internet your users have (VPN off). Every IP gets a real TCP + TLS + HTTP test. "
                     "More IPs found = more configs (each IP becomes one config per port per protocol).")
        self.v_conn = Var("TLS")
        self.field(c, "Connection", Seg(["TLS", "No TLS"], self.v_conn, self.on_conn_change))
        self.lbl_conn = self.note(c, "")
        self.v_depth = Var("Normal")
        self.field(c, "Search depth", Seg(list(DEPTH), self.v_depth, self.on_depth_change))
        self.v_family = Var("IPv4")
        self.field(c, "IP version", Seg(list(FAMILY), self.v_family, self.on_family_change))
        self.lbl_family = self.note(c, FAMILY_HELP["v4"])
        self.v_adv = Var(False)
        c.add_widget(Check("Advanced options", self.v_adv, command=self.toggle_adv))
        self.slot_adv = Holder()
        c.add_widget(self.slot_adv)
        self.adv_box = VBox(spacing=dp(9))
        g = GridLayout(cols=2, spacing=dp(8), size_hint_y=None, row_default_height=dp(68), row_force_default=True)
        g.bind(minimum_height=g.setter("height"))
        self.adv_box.add_widget(g)
        self.s_count = self._mini(g, "IPs to try", 0, 0)
        self.s_target = self._mini(g, "Stop after N clean", 0, 1)
        self.e_keep = self._mini(g, "Keep best N", 0, 2)
        self.s_threads = self._mini(g, "Threads", 1, 0)
        self.s_timeout = self._mini(g, "Timeout (s)", 1, 1, numeric=False)
        self.s_rounds = self._mini(g, "Rounds / IP", 1, 2)
        self.s_port = self._mini(g, "Port", 2, 0)
        self.s_speedtop = self._mini(g, "Speed-test top N", 2, 1)
        self.s_host, _ = self.row(self.adv_box, "Test domain (SNI)", placeholder="empty = speed.cloudflare.com")
        self.v_mode_scan = Var("spread")
        self.field(self.adv_box, "Sampling", Seg(["spread", "random"], self.v_mode_scan))
        self.v_verify, self.v_neigh = Var(True), Var(True)
        self.v_speed, self.v_auto = Var(False), Var(True)
        for text, var in (("Verify certificate", self.v_verify), ("Probe neighbours", self.v_neigh),
                          ("Download speed test", self.v_speed), ("Auto-fix SNI / cert", self.v_auto)):
            self.adv_box.add_widget(Check(text, var))
        self.s_custom = TextBox(h=84, size=12)
        self.field(self.adv_box, "Your own IPs / CIDR ranges, IPv4 or IPv6 (one per line, empty = all official Cloudflare ranges)", self.s_custom)
        self.btn_scan = b_primary("Start scan", self.on_scan, h=48)
        self.btn_stop = b_color("Stop", self.on_stop, "#7a2a3c", "#9a3548", h=48)
        self.btn_stop.configure(state="disabled")
        c.add_widget(btn_row(self.btn_scan, self.btn_stop, weights=[2, 1]))

        c2 = raised(page)
        self.disc = Disc()
        c2.add_widget(self.disc)
        st = HBox(spacing=dp(8))
        self.big_found = self._stat(st, "FOUND", GOOD)
        self.big_tested = self._stat(st, "TESTED", ACC)
        self.big_best = self._stat(st, "BEST MS", WARN)
        c2.add_widget(st)
        self.lbl_stats = Text("Ready.", color=SUB, size=13, halign="center")
        c2.add_widget(self.lbl_stats)

        c3 = raised(page, "Results")
        self.res_box = VBox(spacing=dp(6))
        c3.add_widget(self.res_box)
        self.fill_tree([])

    def _stat(self, parent, label, color):
        f = Panel(bg=FIELD, radius=12, border=EDGE, auto=True, padding=[dp(4), dp(8)], spacing=dp(2))
        v = Text("0", color=color, size=24, bold=True, halign="center")
        f.add_widget(v)
        f.add_widget(Text(label, color=SUB, size=10, halign="center"))
        parent.add_widget(f)
        return v

    def _mini(self, parent, label, r, c, numeric=True):
        box = VBox(spacing=dp(4))
        box.add_widget(Text(label, color=SUB, size=12))
        e = Entry(numeric=numeric)
        box.add_widget(e)
        parent.add_widget(box)
        return e

    def toggle_adv(self):
        if self.v_adv.get():
            set_children(self.slot_adv, self.adv_box)
        else:
            self.slot_adv.clear_widgets()

    def on_conn_change(self, _=None):
        tls = self.v_conn.get() == "TLS"
        self.set_entry(self.s_port, "443" if tls else "80")
        self.refresh_ports()
        self.lbl_conn.configure(
            text=("Encrypted (TLS) on ports 443 / 8443 / 2053 / 2083 / 2087 / 2096. Best choice for most networks." if tls else
                  "Plain WebSocket on ports 80 / 8080 / 8880 / 2052 / 2082 / 2086 / 2095. Usually needs your own domain on Cloudflare "
                  "(workers.dev / pages.dev often force HTTPS)."))

    def on_family_change(self, _=None):
        self.lbl_family.configure(text=FAMILY_HELP[FAMILY.get(self.v_family.get(), "v4")])

    def on_depth_change(self, _=None):
        p = DEPTH.get(self.v_depth.get(), DEPTH["Normal"])
        for e, k in ((self.s_count, "count"), (self.s_target, "target"), (self.e_keep, "keep"), (self.s_threads, "threads")):
            self.set_entry(e, str(p[k]))

    def scan_form(self) -> dict:
        return {
            "host": self.s_host.get().strip(), "port": self.s_port.get().strip(), "count": self.s_count.get().strip(),
            "threads": self.s_threads.get().strip(), "timeout": self.s_timeout.get().strip(), "rounds": self.s_rounds.get().strip(),
            "target": self.s_target.get().strip(), "speed_top": self.s_speedtop.get().strip(), "mode": self.v_mode_scan.get(),
            "verify": bool(self.v_verify.get()), "neighbors": bool(self.v_neigh.get()), "ws": False,
            "speed": bool(self.v_speed.get()), "auto": bool(self.v_auto.get()), "custom": self.s_custom.get("1.0", "end").strip(),
            "family": FAMILY.get(self.v_family.get(), "v4"),
        }

    def fill_scan_form(self, d: dict):
        dflt = dataclasses.asdict(Config())
        self.on_depth_change()
        for e, k in ((self.s_port, "port"), (self.s_count, "count"), (self.s_threads, "threads"), (self.s_timeout, "timeout"),
                     (self.s_rounds, "rounds"), (self.s_target, "target"), (self.s_speedtop, "speed_top")):
            if k in ("count", "threads", "target"):
                continue                     # always come from the Search-depth preset, never from an old config
            self.set_entry(e, str(d.get(k, dflt[k])))
        self.v_mode_scan.set(d.get("mode", "spread"))
        self.v_family.set({v: k for k, v in FAMILY.items()}.get(d.get("family", "v4"), "IPv4"))
        self.on_family_change()
        self.v_verify.set(d.get("verify", True))
        self.v_neigh.set(d.get("neighbors", True))
        self.v_speed.set(d.get("speed", False))
        self.v_auto.set(d.get("auto", True))
        self.s_custom.delete("1.0", "end")
        self.s_custom.insert("1.0", d.get("custom", ""))

    def keep_count(self) -> int:
        try:
            return max(1, min(1000, int(self.e_keep.get().strip())))
        except ValueError:
            return 100

    def on_scan(self):
        if self.job and self.job.phase in ("diagnosing", "scanning", "speed", "finishing"):
            return
        cfg = Config.from_dict(self.scan_form())
        self.job = ScanJob(cfg, self.log)
        job = self.job
        self.shown_found = -1
        self.disc.set_blips([])
        self.disc.mode = "scan"
        self.disc.caption = f"scanning {cfg.host}:{cfg.port} ({'TLS' if cfg.tls else 'no TLS'})"
        self.btn_scan.configure(state="disabled", text="Scanning...")
        self.btn_stop.configure(state="normal")
        self.fill_tree([])
        self.update_nav()
        self.after(0, self.poll_scan)

        def go():
            job.run()
            self.after(0, self.scan_finished)
        threading.Thread(target=go, daemon=True).start()

    def on_stop(self):
        if self.job:
            self.job.stop.set()
            self.log("Stopping...")

    def poll_scan(self):
        job = self.job
        if not job:
            return
        s = job.snapshot()
        self.big_found.configure(text=str(s["found"]))
        self.big_tested.configure(text=str(s["tested"]))
        if s["results"]:
            self.big_best.configure(text=str(min(r["total"] for r in s["results"])))
        self.lbl_stats.configure(text=f"{s['phase']}  \u2022  {s['tested']}/{s['total']}  \u2022  {s['elapsed']}s")
        if s["total"]:
            self.progress.set(min(1.0, s["tested"] / s["total"]))
        if s["found"] != self.shown_found:
            self.shown_found = s["found"]
            self.fill_tree(s["results"])
            self.disc.set_blips([(r["ip"], r["score"]) for r in s["results"]])
        if s["phase"] in ("diagnosing", "scanning", "speed", "finishing", "idle"):
            self.after(500, self.poll_scan)

    def fill_tree(self, results):
        box = self.res_box
        box.clear_widgets()
        rows = sorted(results, key=lambda r: -r["score"])
        if not rows:
            box.add_widget(Text("Nothing yet - the best IPs appear here while the scan runs.", color=SUB, size=12))
            return
        for n, r in enumerate(rows[:MAX_ROWS]):
            box.add_widget(ResRow(r, n))
        if len(rows) > MAX_ROWS:
            box.add_widget(Text(f"Showing the best {MAX_ROWS} of {len(rows)} IPs (all of them are used by the build).", color=SUB, size=11))

    def scan_finished(self):
        self.btn_scan.configure(state="normal", text="Start scan")
        self.btn_stop.configure(state="disabled")
        self.disc.mode = "idle"
        s = self.job.snapshot() if self.job else None
        if s:
            self.fill_tree(s["results"])
            self.disc.set_blips([(r["ip"], r["score"]) for r in s["results"]])
            self.disc.caption = f"{s['found']} clean IPs" if s["results"] else "nothing found - see the log"
            self.disc.draw()
            self.lbl_stats.configure(text=f"{s['phase']}  \u2022  {s['found']} clean of {s['tested']} tested  \u2022  {s['elapsed']}s"
                                          + ("   -  press Next" if s["results"] else ""), text_color=GOOD if s["results"] else WARN)
            if not s["results"]:
                self.log("ERROR: no clean IP found - see the messages above for the reason.")
        self.update_nav()

    # ================================================================ 3 - build
    def build_step_build(self, page):
        c = raised(page, "Ready to build")
        self.lbl_sum = Text("", color=TXT, size=14)
        c.add_widget(self.lbl_sum)
        self.note(c, "One click: the panel is deployed, your IPs are re-checked on the new worker, the best ones are written into the panel, "
                     "and every config is generated. Names, passwords and paths are created automatically.")
        self.v_mode = Var(MODE_WORKERS)
        self.field(c, "Deploy to", Seg([MODE_WORKERS, MODE_PAGES], self.v_mode, size=12))
        self.note(c, "Tip: pages.dev is filtered on many networks (the config's SNI is that name). Workers or your own domain is safer.")
        self.e_remark, _ = self.row(c, "Config name", placeholder="Aminium")
        self.note(c, "Every config shows up in your VPN app as  NAME-vless-IP-port.  English letters, digits, - . _  (max 24).")
        self.e_maxcfg, _ = self.row(c, "Max configs (total)", placeholder="150", numeric=True)
        self.note(c, "Total number of configs is kept at or below this (IPs x ports x 2 protocols). Fewer ports = more IPs fit in.")
        self.v_ports = {p: Var(True) for p in TLS_PORTS + PLAIN_PORTS}
        self.ports_tls_box, self.ports_plain_box = VBox(spacing=dp(2)), VBox(spacing=dp(2))
        for box, plist in ((self.ports_tls_box, TLS_PORTS), (self.ports_plain_box, PLAIN_PORTS)):
            g2 = GridLayout(cols=2, spacing=dp(4), size_hint_y=None, row_default_height=dp(40), row_force_default=True)
            g2.bind(minimum_height=g2.setter("height"))
            for p in plist:
                ck = Check(str(p), self.v_ports[p])
                ck.size_hint_x = 1
                g2.add_widget(ck)
            box.add_widget(g2)
        self.slot_ports = Holder()
        self.field(c, "Ports the configs may use (tick the ones that work on your network)", self.slot_ports)
        set_children(self.slot_ports, self.ports_tls_box)
        self.v_verify_ws = Var(True)
        c.add_widget(Check("Test the IPs on my new worker (real WebSocket, with and without TLS fragment)", self.v_verify_ws))
        self.e_proxy, _ = self.row(c, "Proxy (optional)", placeholder="127.0.0.1:10809   or   socks5h://127.0.0.1:10808",
                                   on_blur=lambda: self.use_proxy())
        self.note(c, "Only for connecting to your panel / worker (pages.dev, workers.dev) after it is built. Put your VPN app's local proxy port here "
                     "(v2rayN: 10809 HTTP, 10808 SOCKS). The IP scan and the Cloudflare API stay direct, so the VPN can stay in proxy mode.")
        self.src_row_holder = Holder()
        c.add_widget(self.src_row_holder)
        self.v_adv3 = Var(False)
        c.add_widget(Check("Advanced (custom domain, source, Telegram...)", self.v_adv3, command=self.toggle_adv3))
        self.slot_adv3 = Holder()
        c.add_widget(self.slot_adv3)
        self.adv3 = VBox(spacing=dp(9))
        self.e_domain, _ = self.row(self.adv3, "Custom domain", placeholder="sub.yourdomain.com (zone in this account)")
        self.e_source, sr = self.row(self.adv3, "Source zip / folder", placeholder="aminium-pages.zip")
        sr.add_widget(btn_row(b_soft("Pick zip", self.pick_zip, h=38), b_soft("Pick folder", self.pick_dir, h=38)))
        self.e_project, _ = self.row(self.adv3, "Project name")
        self.e_pass, _ = self.row(self.adv3, "ADMIN_PASSWORD")
        self.e_panel, _ = self.row(self.adv3, "PANEL_PATH")
        self.e_wspath, _ = self.row(self.adv3, "WS path")
        self.e_cron, _ = self.row(self.adv3, "CRON_SECRET")
        self.e_uuid, _ = self.row(self.adv3, "UUID")
        self.e_decoy, _ = self.row(self.adv3, "DECOY_URL", placeholder="https://example.com")
        self.e_tgtoken, _ = self.row(self.adv3, "TG_TOKEN")
        self.e_tgsecret, _ = self.row(self.adv3, "TG_SECRET")
        self.e_tgadmins, _ = self.row(self.adv3, "TG_ADMINS", placeholder="123456789,987654321")
        self.v_d1 = Var(True)
        self.adv3.add_widget(Check("Create D1 database (traffic quotas)", self.v_d1))
        self.adv3.add_widget(b_soft("Re-roll random values", self.roll_all, h=40))
        self.btn_build = b_primary("Build my configs", self.on_build, h=52, size=16)
        c.add_widget(self.btn_build)

        c2 = raised(page)
        self.disc2 = Disc()
        c2.add_widget(self.disc2)
        self.lbl_stage = Text("Waiting for you.", color=TXT, size=14, bold=True, halign="center")
        c2.add_widget(self.lbl_stage)

    def use_proxy(self, announce=False):
        p = apply_proxy(self.e_proxy.get())
        if announce and p:
            if p.startswith("socks"):
                try:
                    import socks  # noqa: F401  (PySocks)
                except Exception:
                    self.log("ERROR: socks proxies need:  pip install requests[socks]   (or use the HTTP port, e.g. 127.0.0.1:10809)")
            self.log(f"Panel / worker connections go through {p} (scan and Cloudflare API stay direct).")
        return p

    def toggle_adv3(self):
        if self.v_adv3.get():
            set_children(self.slot_adv3, self.adv3)
        else:
            self.slot_adv3.clear_widgets()

    def refresh_build_summary(self):
        n = len(self.ips)
        tls = self.v_conn.get() == "TLS"
        ports = len(self.chosen_ports(tls))
        n = min(n, self.keep_limit())
        self.lbl_sum.configure(text=f"{n} clean IPs (+ your worker's own address)  \u00d7  {ports} ports  \u00d7  2 protocols\n=  up to {min((n + 1) * ports * 2, self.max_cfg())} configs\n"
                                    f"Connection: {'TLS' if tls else 'No TLS'}")
        self.disc2.set_blips([(r["ip"], r["score"]) for r in (self.job.snapshot()["results"] if self.job else [])])
        self.disc2.caption = "ready"
        self.disc2.draw()
        if self.e_source.get().strip() and Path(self.e_source.get().strip()).exists():
            self.src_row_holder.clear_widgets()
        elif not self.src_row_holder.children:
            self.note(self.src_row_holder, "aminium-pages.zip was not found inside the app: open 'Advanced' and pick it.", color=WARN)

    def roll_all(self):
        self.set_entry(self.e_project, rnd_name())
        self.set_entry(self.e_pass, rnd(20))
        self.set_entry(self.e_panel, "/" + rnd(10, LOWER))
        self.set_entry(self.e_wspath, "/stream/" + rnd(18, LOWER))
        self.set_entry(self.e_cron, rnd(24))
        self.set_entry(self.e_uuid, str(uuidlib.uuid4()))

    def max_cfg(self) -> int:
        try:
            return max(1, min(200, int(self.e_maxcfg.get().strip())))
        except ValueError:
            return 150

    def chosen_ports(self, tls) -> list:
        src = TLS_PORTS if tls else PLAIN_PORTS
        sel = [p for p in src if self.v_ports[p].get()]
        return sel or [src[0]]

    def refresh_ports(self):
        set_children(self.slot_ports, self.ports_tls_box if self.v_conn.get() == "TLS" else self.ports_plain_box)

    def apply_ports(self):
        """Push the chosen ports / limit into the engine (panel settings + link expansion + total cap)."""
        global MAX_LINKS
        PANEL_STYLE["ports"] = self.chosen_ports(True)
        PANEL_STYLE["portsHttp"] = self.chosen_ports(False)
        CHOSEN_PORTS[True], CHOSEN_PORTS[False] = PANEL_STYLE["ports"], PANEL_STYLE["portsHttp"]
        MAX_LINKS = self.max_cfg()

    def keep_limit(self) -> int:
        """How many clean IPs fit under the config limit: (IPs + worker address) x ports x 2 protocols <= max."""
        per = len(self.chosen_ports(self.v_conn.get() == "TLS")) * 2
        return max(1, min(self.keep_count(), self.max_cfg() // per - 1))

    @staticmethod
    def clean_remark(v) -> str:
        """Same rule as the worker: letters / digits / _ - . only, 24 characters max."""
        return re.sub(r"[^\w\-.]", "", str(v or ""), flags=re.ASCII)[:24] or "Aminium"

    def on_rename(self):
        rec = self.rec
        if not rec or self.busy:
            return
        name = self.clean_remark(self.e_rename.get())
        self.set_entry(self.e_rename, name)
        self.busy = True
        self.lbl_style.configure(text="applying...", text_color=WARN)

        def work():
            try:
                ROUTE_IPS[:] = list(rec.get("ips") or ROUTE_IPS)
                panel_set(rec["base"], rec["panel_path"], rec["password"], {"remark": name}, self.log)
                rec["remark"] = name
                self.out = fetch_configs(rec["sub"], self.log, rec.get("tls", True))
                self.log(f"Config name changed to {name}.")
                msg, col = "name applied", GOOD
            except Exception as e:
                self.log(f"ERROR: could not change the name: {e}")
                msg, col = "failed", BAD
            self.busy = False

            def ui():
                self.lbl_style.configure(text=msg, text_color=col)
                self.save_cfg()
                self.render_output()
            self.after(0, ui)
        threading.Thread(target=work, daemon=True).start()

    # ---- manual pick from the phone (Android system file picker, falls back to the built-in chooser)
    def _saf_pick(self) -> bool:
        if kplatform != "android":
            return False
        try:
            from android import activity  # type: ignore
            from jnius import autoclass  # type: ignore
            Intent = autoclass("android.content.Intent")
            Act = autoclass("org.kivy.android.PythonActivity")
            REQ = 4711

            def on_result(request, result, intent):
                if request != REQ:
                    return
                try:
                    activity.unbind(on_activity_result=on_result)
                except Exception:
                    pass
                if result != -1 or intent is None:          # -1 = RESULT_OK
                    return
                uri = intent.getData()
                threading.Thread(target=self._copy_picked, args=(uri,), daemon=True).start()
            activity.bind(on_activity_result=on_result)
            it = Intent(Intent.ACTION_OPEN_DOCUMENT)
            it.addCategory(Intent.CATEGORY_OPENABLE)
            it.setType("*/*")
            Act.mActivity.startActivityForResult(it, REQ)
            return True
        except Exception as e:
            self.log(f"System file picker not available ({e}); using the built-in chooser.")
            return False

    def _copy_picked(self, uri):
        """Copy the chosen file into the app folder (the system picker only hands out a content:// stream)."""
        try:
            from jnius import autoclass  # type: ignore
            Act = autoclass("org.kivy.android.PythonActivity")
            Array = autoclass("java.lang.reflect.Array")
            Byte = autoclass("java.lang.Byte")
            ins = Act.mActivity.getContentResolver().openInputStream(uri)
            buf = Array.newInstance(Byte.TYPE, 65536)
            data = bytearray()
            while True:
                n = ins.read(buf)
                if n < 0:
                    break
                data += bytes(b & 0xFF for b in buf[:n])
            ins.close()
            dest = APP_DIR / "picked-source.zip"
            dest.write_bytes(bytes(data))
            if not zipfile.is_zipfile(dest):
                raise CFError("the chosen file is not a .zip")
            self.after(0, lambda: self.set_entry(self.e_source, str(dest)))
            self.log(f"Source loaded from your phone ({len(data) // 1024} KB).")
        except Exception as e:
            self.log(f"ERROR: could not read the chosen file: {e}")

    def _choose(self, title, dirselect, filters):
        """File / folder picker (replaces the desktop dialog)."""
        def open_picker(*_):
            start = "/storage/emulated/0" if kplatform == "android" else str(Path.home())
            if not os.path.isdir(start):
                start = str(BUNDLE_DIR)

            def build(box, close):
                box.add_widget(Text(title, size=16, bold=True))
                fc = FileChooserListView(path=start, filters=filters, dirselect=dirselect, size_hint_y=None, height=dp(340))
                box.add_widget(fc)

                def ok():
                    sel = fc.selection[0] if fc.selection else (fc.path if dirselect else "")
                    if sel:
                        self.set_entry(self.e_source, sel)
                    close()
                box.add_widget(btn_row(b_primary("Select", ok, h=42), b_soft("Cancel", close, h=42)))
            self.modal(build, width=0.95)
        if kplatform == "android":
            try:
                from android.permissions import Permission, request_permissions  # type: ignore
                request_permissions([Permission.READ_EXTERNAL_STORAGE, Permission.WRITE_EXTERNAL_STORAGE],
                                    lambda perms, grants: Clock.schedule_once(open_picker, 0))
                return
            except Exception as e:
                self.log(f"Storage permission request failed: {e}")
        open_picker()

    def pick_zip(self):
        if self._saf_pick():
            return
        self._choose("Pick aminium-pages.zip", False, ["*.zip"])

    def pick_dir(self):
        self._choose("Pick the source folder", True, [])

    def fill_from_cfg(self):
        c = self.cfg
        default_zip = BUNDLE_DIR / "aminium-pages.zip"
        self.set_entry(self.e_source, c.get("source") or (str(default_zip) if default_zip.exists() else ""))
        self.set_entry(self.e_domain, c.get("custom_domain", ""))
        self.set_entry(self.e_decoy, c.get("decoy", ""))
        self.set_entry(self.e_remark, c.get("remark", "Aminium"))
        self.set_entry(self.e_maxcfg, c.get("max_cfg") or "150")
        for _p in TLS_PORTS:
            self.v_ports[_p].set(_p in (c.get("ports_tls") or TLS_PORTS))
        for _p in PLAIN_PORTS:
            self.v_ports[_p].set(_p in (c.get("ports_plain") or PLAIN_PORTS))
        self.set_entry(self.e_proxy, c.get("proxy", ""))
        self.use_proxy()
        self.set_entry(self.e_tgtoken, c.get("tg_token", ""))
        self.set_entry(self.e_tgsecret, c.get("tg_secret", ""))
        self.set_entry(self.e_tgadmins, c.get("tg_admins", ""))
        self.v_d1.set(c.get("use_d1", True))
        self.v_verify_ws.set(c.get("verify_ws", True))
        self.v_mode.set(c.get("mode") if c.get("mode") in (MODE_PAGES, MODE_WORKERS) else MODE_WORKERS)
        self.v_conn.set(c.get("conn") if c.get("conn") in ("TLS", "No TLS") else "TLS")
        self.v_depth.set(c.get("depth") if c.get("depth") in DEPTH else "Normal")
        self.fill_scan_form(c.get("scan", {}))
        self.on_conn_change()               # sets the port from TLS / No TLS

    def on_build(self):
        if self.busy:
            return
        project = self.e_project.get().strip().lower()
        source = self.e_source.get().strip()
        if not self.ips:
            return self.log("ERROR: no clean IPs yet - go back to step 2.")
        if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,56}", project or ""):
            return self.log("ERROR: project name: lowercase letters, digits and '-' only.")
        if not source or not Path(source).exists():
            self.v_adv3.set(True)
            self.toggle_adv3()
            return self.log("ERROR: source zip not found - pick aminium-pages.zip in Advanced.")
        if not self.e_pass.get():
            return self.log("ERROR: ADMIN_PASSWORD is empty.")
        panel = self.e_panel.get().strip()
        if panel and not panel.startswith("/"):
            panel = "/" + panel
            self.set_entry(self.e_panel, panel)
        self.use_proxy(announce=True)
        self.apply_ports()
        self.log(f"Config limit {self.max_cfg()}: using up to {self.keep_limit()} clean IPs on ports {self.chosen_ports(self.v_conn.get() == 'TLS')}.")
        ROUTE_IPS[:] = list(self.pool or self.ips)
        ROUTES.clear()
        DIRECT_BAD.clear()
        self.save_cfg()
        self.busy = True
        self.out = None
        self.btn_build.configure(state="disabled", text="Building...")
        self.disc2.mode = "build"
        self.disc2.caption = "building"
        self.progress.set(0)
        self.update_nav()
        mode = "workers" if self.v_mode.get() == MODE_WORKERS else "pages"
        form = {
            "pass": self.e_pass.get(), "ws_path": self.e_wspath.get().strip(), "cron": self.e_cron.get().strip(),
            "uuid": self.e_uuid.get().strip(), "decoy": self.e_decoy.get(), "tg_token": self.e_tgtoken.get(),
            "tg_secret": self.e_tgsecret.get(), "tg_admins": self.e_tgadmins.get(), "domain": self.e_domain.get().strip().lower(),
            "d1": bool(self.v_d1.get()), "verify_ws": bool(self.v_verify_ws.get()), "scan": self.scan_form(),
            "ips": list(self.pool or self.ips), "keep": self.keep_limit(), "tls": self.v_conn.get() == "TLS",
            "remark": self.clean_remark(self.e_remark.get()),
        }
        threading.Thread(target=self.build_worker, args=(project, source, panel, mode, form), daemon=True).start()

    def build_worker(self, project, source, panel, mode, f):
        ok = False
        warned = False
        try:
            cf = CF(self.token, self.log, self.email)
            self.stage("Checking your token...", 0.04)
            cf.verify()
            if not self.accounts:
                self.accounts = cf.accounts()
            acc = self.selected_account_id()
            if not acc:
                raise CFError("No Cloudflare account found for this token")
            files = load_source(source)
            self.log(f"Files: {', '.join(files)}  ({sum(len(v) for v in files.values()) // 1024} KB)")
            if not cf.global_key:
                try:
                    cf.req("GET", f"/accounts/{acc}/" + ("workers/scripts" if mode == "workers" else "pages/projects?per_page=1"))
                except CFError as e:
                    if "10000" in str(e) or "403" in str(e):
                        need = "Workers Scripts: Edit" if mode == "workers" else "Cloudflare Pages: Edit"
                        raise CFError(f"Token has no '{need}' permission. Change the token in step 1.")
                    raise
                try:
                    cf.req("GET", f"/accounts/{acc}/storage/kv/namespaces?per_page=1")
                except CFError:
                    raise CFError("Token has no 'Workers KV Storage: Edit' permission.")
                if f["d1"]:
                    try:
                        cf.req("GET", f"/accounts/{acc}/d1/database?per_page=1")
                    except CFError:
                        raise CFError("Token has no 'D1: Edit' permission (or untick the D1 option in Advanced).")
            self.stage("Creating storage (KV / D1)...", 0.14)
            kv_id = cf.kv_get_or_create(acc, f"{project}-kv")
            d1_id = cf.d1_get_or_create(acc, f"{project}-db") if f["d1"] else None
            proj = None
            if mode != "workers":
                proj = cf.pages_project(acc, project)
                if not proj:
                    proj = cf.pages_create(acc, project)

            env_vars = {"ADMIN_PASSWORD": {"type": "secret_text", "value": f["pass"]}}

            def add(key, val, secret=False):
                val = (val or "").strip()
                if val:
                    env_vars[key] = {"type": "secret_text" if secret else "plain_text", "value": val}
            add("PANEL_PATH", panel)
            if mode != "workers":
                add("CRON_SECRET", f["cron"], True)
            add("UUID", f["uuid"])
            add("DECOY_URL", f["decoy"])
            add("TG_TOKEN", f["tg_token"], True)
            add("TG_SECRET", f["tg_secret"], True)
            add("TG_ADMINS", f["tg_admins"])

            cron_url = ""
            self.stage("Uploading the panel...", 0.3)
            if mode == "workers":
                cf.workers_deploy(acc, project, files["_worker.js"], kv_id, d1_id, env_vars)
                wsub = cf.workers_account_subdomain(acc, project)
                try:
                    cf.workers_enable_subdomain(acc, project)
                except CFError as e:
                    self.log(f"workers.dev route toggle: {e}")
                try:
                    cf.workers_set_cron(acc, project)
                except CFError as e:
                    self.log(f"Cron trigger not set (add it in Settings > Triggers): {e}")
                status = "worker:success"
                base = f"https://{project}.{wsub}.workers.dev"
            else:
                cf.pages_configure(acc, project, kv_id, d1_id, env_vars)
                dep = cf.pages_deploy(acc, project, files)
                dep_id = dep.get("id")
                status = "unknown"
                for _ in range(40):
                    time.sleep(3)
                    try:
                        dd = cf.pages_deployment_status(acc, project, dep_id)
                    except CFError as e:
                        self.log(f"status check: {e}")
                        continue
                    st = dd.get("latest_stage", {})
                    status = f"{st.get('name')}:{st.get('status')}"
                    self.stage(f"Pages deployment: {status}", 0.4)
                    if (st.get("name") == "deploy" and st.get("status") in ("success", "failure")) or st.get("status") == "failure":
                        break
                base = f"https://{(proj or {}).get('subdomain') or f'{project}.pages.dev'}"
                if f["cron"]:
                    cron_url = f"{base}/cron/{f['cron']}"

            if f["domain"]:
                try:
                    zid = cf.zone_for(f["domain"])
                    if not zid:
                        raise CFError("the domain's zone was not found in this account (token needs Zone: Read)")
                    if mode == "workers":
                        cf.workers_attach_domain(acc, project, f["domain"], zid)
                    else:
                        cf.pages_attach_domain(acc, project, f["domain"], zid, base.replace("https://", ""))
                    base = f"https://{f['domain']}"
                    self.log(f"Custom domain attached: {f['domain']}")
                except CFError as e:
                    self.log(f"Custom domain failed: {e}  -> keeping {base}")

            panel_path = panel or "/panel"
            self.stage("Waiting for the panel to come online...", 0.5)
            sub_link, sub_user = fetch_sub_link(base, panel_path, f["pass"], self.log, ws_path=f["ws_path"])

            host = host_of(base)
            pool, keep_n, ws_path = f["ips"], f["keep"], (f["ws_path"] or "/")
            good: list = []
            if f["verify_ws"] and pool:
                self.stage("Reading a real signed WebSocket path from the panel...", 0.54)
                try:
                    r0 = web_session().get(sub_link + "?format=base64", timeout=30, headers={"User-Agent": "AminiumStudio"})
                    for ln in links_from_base64(r0.text):
                        mt = re.search(r"[?&]path=([^&#]+)", ln)
                        if mt:
                            ws_path = unquote(mt.group(1))
                            break
                except Exception as e:
                    self.log(f"Could not read a signed path ({e}); using the plain WS path.")
                modes = [(True, "with TLS fragment"), (False, "without fragment")] if f["tls"] else [(False, "")]
                scores: dict = {}
                for n, (frag, label) in enumerate(modes):
                    self.stage(f"Testing {len(pool)} IPs on your worker {label}...".replace("  ", " "), 0.58 + 0.12 * n)
                    d = dict(f["scan"])
                    d.update(host=host, ws=True, ws_path=ws_path, custom="\n".join(pool), count=len(pool), target=0, neighbors=False,
                             auto=False, speed=False, rounds=2, port=443 if f["tls"] else 80, fragment=frag)
                    job = ScanJob(Config.from_dict(d), self.log)
                    job.diag_on_empty = False
                    job.run()
                    rows = [r for r in job.snapshot()["results"] if r["ws"]]
                    self.log(f"{len(rows)} of {len(pool)} IPs reach your worker {label}.".replace("  ", " "))
                    for r in rows:
                        scores[r["ip"]] = max(scores.get(r["ip"], 0), r["score"] + (1 if frag else 0))
                good = [ip for ip, _ in sorted(scores.items(), key=lambda kv: -kv[1])][:keep_n]
            elif pool:
                good = pool[:keep_n]            # verification switched off: use them as they are
            if good:
                ROUTE_IPS[:] = good + [x for x in pool if x not in good]      # the panel is reached through the proven IPs first
            if f["verify_ws"] and good and len(good) < keep_n:
                extra = [x for x in pool if x not in good][: keep_n - len(good)]
                if extra:
                    self.log(f"{len(good)} IPs passed the worker test; adding {len(extra)} more clean IPs (not verified on the worker) so you get "
                             "many configs - your app's ping test will pick the live ones.")
                    good = good + extra
            warned = bool(f["verify_ws"] and pool and not good)
            if warned:
                good = pool[:keep_n]            # the worker test failed for every IP: still build the configs from the clean IPs found
                self.log(f"WARNING: no clean IP could reach your worker from this network (even with TLS fragment). The configs are still built "
                         f"from the {len(good)} clean IPs found (plus the worker's own address {host}). If none connects, this network blocks that "
                         "domain: deploy to Workers instead of Pages, or attach your own domain (Advanced > Custom domain).")
                self.stage("Worker test failed for all IPs - building configs from the clean IPs anyway.", 0.75)
            # the worker's own address always goes first (the same config the plain deployer makes - known to work), then the clean IPs
            addrs = [host] + good
            self.stage("Writing the address list and settings into the panel...", 0.84)
            extra = dict(PANEL_STYLE)
            extra.update(tls=f["tls"], fingerprint="chrome", remark=f["remark"])
            panel_apply_clean(base, panel_path, f["pass"], addrs, self.log, extra=extra)
            ips = good

            self.stage("Generating configs...", 0.92)
            out = fetch_configs(sub_link, self.log, f["tls"])
            by_port = collections.Counter(m.group(1) for m in (re.search(r"@(?:\[[^\]]+\]|[^:/?#]+):(\d+)", ln) for ln in out["links"]) if m)
            self.log("Config links per port: " + (", ".join(f"{k}: {v}" for k, v in sorted(by_port.items())) or "-"))
            rec = {"project": project, "mode": mode, "account": acc, "base": base, "panel_path": panel_path, "password": f["pass"],
                   "sub": sub_link, "ws_path": f["ws_path"], "kv_id": kv_id, "d1_id": d1_id, "ips": ips, "tls": f["tls"],
                   "fp": "chrome", "remark": f["remark"], "created": time.strftime("%Y-%m-%d %H:%M")}
            self.deployments.append(rec)
            self.rec, self.out = rec, out
            text = (f"Aminium deployed ({status})\nSite:        {base}\nPanel:       {base}{panel_path}\nPassword:    {f['pass']}\n"
                    f"Sub link:    {sub_link}\nCron URL:    {cron_url or ('(native cron, every 15 min)' if mode == 'workers' else '-')}\n"
                    f"Clean IPs:   {len(ips)}\nConfig links: {len(out['links'])}\nKV id:       {kv_id}\nD1 id:       {d1_id or '-'}\n")
            try:
                RESULT_FILE.write_text(text, encoding="utf-8")
            except Exception:
                pass
            for line in text.strip().splitlines():
                self.log(line)
            if cron_url:
                self.log("Pages has no Cron Triggers: call the Cron URL every 15 min from cron-job.org (or similar).")
            if not warned:
                self.stage(f"Done: {len(out['links'])} configs ready.", 1.0)
            else:
                self.set_progress(1.0)
            ok = True
        except Exception as e:
            self.log(f"ERROR: {e}")
            self.stage("Something went wrong - see the log.", 0)
        finally:
            self.busy = False

            def fin():
                self.disc2.mode = "idle"
                self.disc2.caption = "done" if ok else "failed"
                self.disc2.draw()
                self.btn_build.configure(state="normal", text="Build my configs")
                if ok:
                    self.roll_all()          # next build gets a brand-new random identity
                self.save_cfg()
                self.update_nav()
                if ok:
                    self.goto(3)
            self.after(0, fin)

    # ================================================================ 4 - configs
    def build_step_out(self, page):
        top = raised(page)
        r = HBox(spacing=dp(8))
        self.lbl_big = Text("Your configs", color=TXT, size=20, bold=True, size_hint_x=1)
        r.add_widget(self.lbl_big)
        top.add_widget(r)
        self.cb_dep = Pick(["(none)"], command=self.on_pick_dep)
        self.field(top, "Deployment", self.cb_dep)
        self.out_info = TextBox(readonly=True, h=74, size=12)
        top.add_widget(self.out_info)
        top.add_widget(btn_grid(b_soft("Open panel", self.out_open_panel), b_soft("Copy panel details", self.out_copy_details),
                                b_color("Save all files + QR", self.out_save_all, "#1d8f63", "#27a574"),
                                b_soft("Re-scan IPs", lambda: self.goto(1))))
        self.v_tls_out = Var("TLS")
        self.field(top, "Style", Seg(["TLS", "No TLS"], self.v_tls_out, self.on_restyle))
        self.cb_fp = Pick(FINGERPRINTS, command=self.on_restyle)
        self.field(top, "Fingerprint", self.cb_fp)
        self.e_rename = Entry(hint="Aminium")
        self.field(top, "Config name", self.e_rename)
        top.add_widget(b_soft("Apply name", self.on_rename, h=40))
        self.lbl_style = Text("", color=SUB, size=13)
        top.add_widget(self.lbl_style)

        self.seg = Seg([x[1] for x in FORMATS] + [RAW], None, self.on_pick_fmt, scroll=True, size=13)
        page.add_widget(self.seg)
        self.lbl_help = Text("", color=SUB, size=12)
        page.add_widget(self.lbl_help)

        mid = raised(page)
        self.e_url = Entry()
        mid.add_widget(self.e_url)
        self.btn_copy_url = b_primary("Copy link", self.out_copy_url, h=42)
        self.btn_copy_content = b_soft("Copy file content", self.out_copy_content, h=42)
        self.btn_copy_all = b_soft("Copy all links", self.out_copy_all, h=42)
        self.bb = HBox(spacing=dp(8))
        mid.add_widget(self.bb)
        qa = AnchorLayout(size_hint_y=None, height=dp(284), anchor_x="center", anchor_y="center")
        self.qr = QRView(size=(dp(280), dp(280)))
        qa.add_widget(self.qr)
        mid.add_widget(qa)
        self.lbl_qr = Text("", color=SUB, size=12, halign="center")
        mid.add_widget(self.lbl_qr)
        self.slot_view = Holder()
        mid.add_widget(self.slot_view)
        self.preview = TextBox(readonly=True, h=260, size=11)
        self.lst_frame = VBox(spacing=dp(6))
        self.lbl_page = Text("", color=SUB, size=12, halign="center")
        self.lst_frame.add_widget(btn_row(b_soft("Prev", lambda: self.page_links(-1), h=36), self.lbl_page,
                                          b_soft("Next page", lambda: self.page_links(1), h=36), weights=[1, 1.4, 1]))
        self.lst_box = VBox(spacing=dp(5))
        self.lst_frame.add_widget(self.lst_box)

    def page_links(self, d):
        self.raw_page += d
        self.fill_links()

    def fill_links(self):
        links = self.out["links"] if self.out else []
        n = len(links)
        pages = max(1, (n + PER_PAGE - 1) // PER_PAGE)
        self.raw_page = max(0, min(pages - 1, self.raw_page))
        a = self.raw_page * PER_PAGE
        b = min(n, a + PER_PAGE)
        self.lbl_page.configure(text=(f"{a + 1}-{b} of {n}" if n else "0 links"))
        self.lst_box.clear_widgets()
        for ln in links[a:b]:
            self.lst_box.add_widget(LinkRow(ln, self.select_link, selected=(ln == self.sel_link)))

    def select_link(self, link):
        self.sel_link = link
        self.set_entry(self.e_url, link)
        self.draw_qr(link)
        for w in self.lst_box.children:
            if isinstance(w, LinkRow):
                w.set_selected(w.link == link)

    def refresh_dep_menu(self):
        labels = [self.dep_label(d) for d in reversed(self.deployments)] or ["(none)"]
        self.cb_dep.configure(values=labels)
        if self.rec:
            self.cb_dep.set(self.dep_label(self.rec))

    @staticmethod
    def dep_label(d):
        return f"{d['project']}  ({d.get('created', '')})"

    def on_pick_dep(self, label=None):
        label = label or self.cb_dep.get()
        for d in self.deployments:
            if self.dep_label(d) == label:
                if d is self.rec and self.out:
                    return
                self.rec, self.out = d, None
                self.log(f"Loading configs of {d['project']} ...")

                def work(d=d):
                    try:
                        ROUTE_IPS[:] = list(d.get("ips") or ROUTE_IPS)
                        out = fetch_configs(d["sub"], self.log, d.get("tls", True)) if d.get("sub") else None
                    except Exception as e:
                        self.log(f"Could not load: {e}")
                        out = None
                    self.out = out
                    self.after(0, self.render_output)
                threading.Thread(target=work, daemon=True).start()
                return

    def render_output(self):
        self.refresh_dep_menu()
        rec, out = self.rec, self.out
        self.out_info.configure(state="normal")
        self.out_info.delete("1.0", "end")
        if not rec:
            self.lbl_big.configure(text="Your configs")
            self.out_info.insert("1.0", "Nothing built yet. Go through steps 1-3, or pick an earlier deployment above.")
            self.out_info.configure(state="disabled")
            return
        n = len(out["links"]) if out else 0
        self.lbl_big.configure(text=f"{n} configs  \u2022  {len(rec.get('ips', []))} clean IPs")
        self.out_info.insert("1.0", f"Panel:     {rec['base']}{rec['panel_path']}\nPassword:  {rec['password']}")
        self.out_info.configure(state="disabled")
        self.v_tls_out.set("TLS" if rec.get("tls", True) else "No TLS")
        self.cb_fp.set(rec.get("fp", "chrome"))
        self.set_entry(self.e_rename, rec.get("remark", "Aminium"))
        if not self.seg.get():
            self.seg.set(FORMATS[0][1])
        self.on_pick_fmt(self.seg.get())

    def on_restyle(self, _=None):
        rec = self.rec
        if not rec or self.busy:
            return
        tls, fp = self.v_tls_out.get() == "TLS", self.cb_fp.get()
        self.busy = True
        self.lbl_style.configure(text="applying...", text_color=WARN)

        def work():
            try:
                ROUTE_IPS[:] = list(rec.get("ips") or ROUTE_IPS)
                panel_set(rec["base"], rec["panel_path"], rec["password"], {"tls": tls, "fingerprint": fp, **PANEL_STYLE}, self.log)
                rec["tls"], rec["fp"] = tls, fp
                self.out = fetch_configs(rec["sub"], self.log, tls)
                self.log(f"Style applied: {'TLS' if tls else 'No TLS'}, fingerprint {fp}.")
                msg, col = "applied", GOOD
            except Exception as e:
                self.log(f"ERROR: could not change the style: {e}")
                msg, col = "failed", BAD
            self.busy = False

            def ui():
                self.lbl_style.configure(text=msg, text_color=col)
                self.save_cfg()
                self.render_output()
            self.after(0, ui)
        threading.Thread(target=work, daemon=True).start()

    def on_pick_fmt(self, label):
        out = self.out
        key = next((k for k, lb, _, _ in FORMATS if lb == label), None)
        self.lbl_help.configure(text=FORMAT_HELP.get(key or RAW, ""))
        if not out:
            self.set_entry(self.e_url, "")
            set_children(self.bb, self.btn_copy_url)
            set_children(self.slot_view, self.preview)
            self.preview.set("No configs available (the panel was not reachable). Open the panel and copy the link from there.")
            self.draw_qr("")
            return
        if label == RAW:
            self.btn_copy_url.configure(text="Copy selected")
            set_children(self.bb, self.btn_copy_url, self.btn_copy_all)
            set_children(self.slot_view, self.lst_frame)
            self.raw_page = 0
            self.sel_link = out["links"][0] if out["links"] else ""
            self.fill_links()
            self.set_entry(self.e_url, "")
            if out["links"]:
                self.select_link(out["links"][0])
            else:
                self.draw_qr("")
        else:
            q = next(q for k, lb, q, _ in FORMATS if lb == label)
            url = out["sub"] + q
            self.btn_copy_url.configure(text="Copy link")
            if key != "auto":
                set_children(self.bb, self.btn_copy_url, self.btn_copy_content)
            else:
                set_children(self.bb, self.btn_copy_url)
            self.set_entry(self.e_url, url)
            set_children(self.slot_view, self.preview)
            self.preview.set((out["text"].get(key) or "(empty)")[:6000])
            self.cur_fmt = key
            self.draw_qr(url)

    def draw_qr(self, text):
        self.qr.set_matrix(None)
        if not text:
            self.lbl_qr.configure(text="")
            return
        if qrcode is None:
            self.lbl_qr.configure(text="QR needs the 'qrcode' package")
            return
        try:
            m = qr_matrix(text)
        except Exception as e:
            self.lbl_qr.configure(text=f"QR not possible for this item ({e})")
            return
        self.qr.set_matrix(m)
        self.lbl_qr.configure(text="Scan with the client app" if self.qr.cell_px() >= 3 else "Dense QR - use the link / file if it will not scan")

    def out_copy_url(self):
        self.copy_text(self.e_url.get(), "Copied.")

    def out_copy_content(self):
        if self.out and self.cur_fmt in self.out["text"]:
            self.copy_text(self.out["text"][self.cur_fmt], "File content copied.")

    def out_copy_all(self):
        if self.out:
            self.copy_text("\n".join(self.out["links"]), f"{len(self.out['links'])} links copied.")

    def out_open_panel(self):
        if self.rec:
            self.open_url(self.rec["base"] + self.rec["panel_path"])

    def out_copy_details(self):
        if self.rec:
            r = self.rec
            self.copy_text(f"Panel: {r['base']}{r['panel_path']}\nPassword: {r['password']}\nSub: {r.get('sub', '')}", "Panel details copied.")

    def out_save_all(self):
        if not (self.rec and self.out):
            return self.log("Nothing to save yet.")
        try:
            folder = save_all(self.rec, self.out, self.log)
            if kplatform == "android":
                try:
                    import shutil
                    pub = Path("/storage/emulated/0/Download/AminiumStudio") / self.rec["project"]
                    pub.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copytree(folder, pub, dirs_exist_ok=True)
                    self.log(f"Also copied to {pub}")
                    folder = pub
                except Exception as e:
                    self.log(f"(Could not copy to the Download folder: {e})")
            self.info("Saved", f"Files and QR codes are in:\n{folder}\n\nThe path was copied to the clipboard.")
            try:
                Clipboard.copy(str(folder))
            except Exception:  # pragma: no cover
                pass
        except Exception as e:
            self.log(f"ERROR: save failed: {e}")


class AminiumApp(App):
    title = APP_NAME

    def build(self):
        Window.clearcolor = C(BG)
        try:
            Window.softinput_mode = "below_target"
        except Exception:  # pragma: no cover
            pass
        if kplatform not in ("android", "ios"):
            Window.size = (430, 860)
        self.wiz = Wizard()
        return self.wiz

    def on_pause(self):
        return True            # keep running (and keep the scan going) when the app is sent to the background

    def on_resume(self):
        pass

    def on_stop(self):
        try:
            self.wiz.shutdown()
        except Exception:  # pragma: no cover
            pass


if __name__ == "__main__":
    AminiumApp().run()
