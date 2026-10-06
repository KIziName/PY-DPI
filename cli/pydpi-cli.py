""" Примеры:
  python pydpi.py start --mode disorder
  python pydpi.py start --mode fake+disorder --ttl 1 --repeats 2 --all
  python pydpi.py test
  python pydpi.py dns
  python pydpi.py list-modes
"""
import argparse
import copy
import ctypes
import functools
import heapq
import ipaddress
import os
import queue
import random
import signal
import socket
import sys
import threading
import time
import traceback

from collections import deque
from dataclasses import dataclass, replace, field

try:
    import pydivert
except ImportError:
    pydivert = None


# ----------------------------- config -----------------------------

APP_TITLE = "PY-DPI"
APP_VERSION = "V1.2-CLI"

PORT_HTTP = 80
PORT_HTTPS = 443

FAKE_SNI_BASE = b"www.microsoft.com"
HTTP_METHODS = (
    b"GET", b"POST", b"HEAD", b"PUT", b"DELETE",
    b"OPTIONS", b"PATCH", b"CONNECT", b"TRACE", b"PRI",
)
HTTP_HEADER_MAX_SCAN = 4096

TLS_CONTENT_HANDSHAKE = 0x16
TLS_HANDSHAKE_CLIENT_HELLO = 0x01
TLS_SNI_EXT_TYPE = 0x0000
TLS_RECORD_HEADER_LEN = 5
TLS_EXT_HEADER_LEN = 4
TLS_MIN_CLIENTHELLO_LEN = 43

SEQ_MASK = 0xFFFFFFFF
SEQ_HALF = 0x7FFFFFFF
CHECKSUM_MASK = 0xFFFF
CHECKSUM_FLIP = 0x0001

CRLF = b"\r\n"
CRLFCRLF = b"\r\n\r\n"
HOST_HEADER = b"host:"
HOST_PORT_SEP = b":"
DOT_BYTE = 0x2E

TTL_MIN, TTL_MAX = 1, 12

MODES = ("split", "disorder", "fake+split", "fake+disorder")
MODES_SPLIT = ("random", "midsld")

IP_WHITELIST_V4 = (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
    "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/4",
)
IP_WHITELIST_V6 = (
    "::1/128", "::/128", "::ffff:0:0/96",
    "fc00::/7", "fe80::/10", "ff00::/8",
)

_WHITELIST_V4_NETS = tuple(ipaddress.ip_network(c) for c in IP_WHITELIST_V4)
_WHITELIST_V6_NETS = tuple(ipaddress.ip_network(c) for c in IP_WHITELIST_V6)


@dataclass(frozen=True)
class DpiConfig:
    disorder_delay_s: float = 0.005
    fake_split_delay_s: float = 0.005
    fake_ttl: int = 1
    fake_repeats: int = 2
    fake_badsum: bool = True
    split_pos: str = "midsld"

    pending_max_bytes: int = 8192
    pending_timeout_s: float = 1.0
    pending_max_packets: int = 32
    pending_flush_interval_s: float = 0.2

    block_quic: bool = True

    @property
    def windivert_filter(self) -> str:
        return (
            f"(tcp and ((tcp.DstPort == {PORT_HTTPS} or tcp.DstPort == {PORT_HTTP}) "
            f"and tcp.PayloadLength > 0)) "
            f"or (udp and (udp.DstPort == {PORT_HTTPS} and udp.PayloadLength > 0))"
        )


RT_SHUTDOWN_GRACE_S = 1.0
RT_PACKET_QUEUE_MAX = 5000
RT_WORKER_JOIN_TIMEOUT_S = 1.5
RT_RECV_JOIN_TIMEOUT_S = 1.0
RT_QUEUE_GET_TIMEOUT_S = 0.2
RT_QUEUE_PUT_TIMEOUT_S = 0.3
RT_DRAIN_GET_TIMEOUT_S = 0.05
RT_WORKER_MAX_WAIT_S = 0.1
RT_WORKER_MIN_WAIT_S = 0.001
RT_IP_CACHE_SIZE = 4096
RT_TEST_DURATION_S = 5

DEFAULT_DOMAINS = (
    "facebook.com", "fbcdn.net", "fb.com", "fbsbx.com", "fb.watch",
    "messenger.com", "m.me", "facebook.net",
    "instagram.com", "cdninstagram.com", "threads.net",
    "whatsapp.com", "whatsapp.net", "wa.me", "whatsapp.org",
    "viber.com", "vb.me", "viber.me", "viber.net", "viber.co",
    "vibercdn.com", "twitter.com", "x.com", "twimg.com", "t.co", "x.ai",
    "discord.com", "discordapp.com", "discordapp.net", "discord.gg",
    "discord.media", "discordactivities.com", "discord.new", "discord.gift",
    "telegram.org", "t.me", "telegram.me", "telegra.ph", "telesco.pe",
    "cdn-telegram.org",
    "youtube.com", "youtu.be", "googlevideo.com", "ytimg.com",
    "youtubemusic.com", "yt.be", "ggpht.com",
    "youtubei.googleapis.com", "youtube.googleapis.com",
    "youtube-nocookie.com", "youtubekids.com",
    "tiktok.com", "tiktokcdn.com", "tiktokv.com", "byteoversea.com",
    "snapchat.com", "snap.com", "sc-cdn.net", "sc-gw.com",
    "github.com", "githubusercontent.com", "githubassets.com",
    "torproject.org", "torproject.net", "tor.eff.org",
    "dns.google", "dns.quad9.net", "dns.nextdns.io",
    "cloudflare-dns.com", "one.one.one.one",
    "dns.adguard.com", "doh.opendns.com",
    "openai.com", "chatgpt.com", "oaiusercontent.com", "oaistatic.com",
    "signal.org", "whispersystems.org",
    "soundcloud.com", "sndcdn.com",
)

DNS_CHECK_DOMAINS = (
    "youtube.com", "googlevideo.com", "instagram.com", "facebook.com",
    "x.com", "discord.com", "telegram.org", "tiktok.com",
    "openai.com", "github.com",
)


# ----------------------------- utils -----------------------------

def is_admin() -> bool:
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


@functools.lru_cache(maxsize=RT_IP_CACHE_SIZE)
def _ip_is_local(s: str, is_v4: bool) -> bool:
    nets = _WHITELIST_V4_NETS if is_v4 else _WHITELIST_V6_NETS
    try:
        addr = ipaddress.ip_address(s)
    except Exception:
        return True
    for net in nets:
        if addr in net:
            return True
    return False


# ----------------------------- state -----------------------------

@dataclass
class PendingState:
    buf: bytes
    ts: float
    packets: list
    first_seq: int


# ----------------------------- engine -----------------------------

class DpiBypass:
    def __init__(self, domains, mode, log_cb, done_cb=None, config=None,
                 bypass_all=False):
        self.domains = set()
        for d in domains:
            d = d.strip().lower().rstrip(".")
            if not d:
                continue
            try:
                b = d.encode("idna")
            except Exception:
                b = d.encode("ascii", "ignore")
            if b:
                self.domains.add(b)

        self.mode = mode
        self.log = log_cb
        self.done_cb = done_cb
        self.cfg = config or DpiConfig()
        self.bypass_all = bool(bypass_all)

        self._lock = threading.Lock()
        self._send_lock = threading.Lock()
        self._stop_event = threading.Event()
        self._shutting_down = False
        self._started = False
        self.running = False
        self.w = None

        self._pending = {}
        self._pending_lock = threading.RLock()

        self.packets_bypassed = 0
        self.packets_quic_dropped = 0
        self.bytes_bypassed = 0
        self._bw = deque()
        self._bw_lock = threading.Lock()

        self._pq = []
        self._pq_seq = 0
        self._pq_cond = threading.Condition(threading.Lock())
        self._worker_thread = None

    # -------- stats --------

    def get_stats(self):
        with self._pending_lock:
            pending_pkts = sum(len(s.packets) for s in self._pending.values())
            pending_conn = len(self._pending)
        now = time.monotonic()
        with self._bw_lock:
            while self._bw and now - self._bw[0][0] > 5.0:
                self._bw.popleft()
            if self._bw:
                span = now - self._bw[0][0]
                bw_bps = sum(n for _, n in self._bw) / max(span, 0.001)
            else:
                bw_bps = 0.0
        return {
            "bypassed": self.packets_bypassed,
            "bytes": self.bytes_bypassed,
            "bw_bps": bw_bps,
            "quic_dropped": self.packets_quic_dropped,
            "pending_pkts": pending_pkts,
            "pending_conn": pending_conn,
        }

    def _mark_bypassed(self, nbytes):
        self.packets_bypassed += 1
        self.bytes_bypassed += nbytes
        with self._bw_lock:
            self._bw.append((time.monotonic(), nbytes))

    # -------- scheduler --------

    def _schedule(self, delay, func):
        with self._pq_cond:
            self._pq_seq += 1
            heapq.heappush(self._pq,
                           (time.monotonic() + delay, self._pq_seq, func))
            self._pq_cond.notify()

    def _worker_loop(self):
        last_flush = time.monotonic()
        while not self._stop_event.is_set():
            due = []
            with self._pq_cond:
                now = time.monotonic()
                while self._pq and self._pq[0][0] <= now:
                    _, _, func = heapq.heappop(self._pq)
                    due.append(func)
            for func in due:
                try:
                    func()
                except Exception:
                    pass

            now = time.monotonic()
            if now - last_flush >= self.cfg.pending_flush_interval_s:
                last_flush = now
                try:
                    self._flush_expired()
                except Exception:
                    pass

            with self._pq_cond:
                if self._stop_event.is_set():
                    return
                wait = RT_WORKER_MAX_WAIT_S
                if self._pq:
                    wait = min(wait, max(0.0,
                                         self._pq[0][0] - time.monotonic()))
                self._pq_cond.wait(max(wait, RT_WORKER_MIN_WAIT_S))

    def stop(self):
        if self._stop_event.is_set():
            return
        self._stop_event.set()
        with self._pq_cond:
            self._pq_cond.notify_all()

    # -------- send helpers --------

    def _send_one(self, packet, recalculate=True):
        with self._lock:
            w = self.w
        if w is None:
            return
        with self._send_lock:
            try:
                w.send(packet, recalculate_checksum=recalculate)
            except TypeError:
                try:
                    w.send(packet)
                except Exception as e:
                    if not (self._stop_event.is_set() or self._shutting_down):
                        self.log(f"send: {e}")
            except Exception as e:
                if not (self._stop_event.is_set() or self._shutting_down):
                    self.log(f"send: {e}")

    def _send_with_checksum(self, packet):
        try:
            packet.recalculate_checksums()
        except Exception:
            pass
        self._send_one(packet, recalculate=False)

    def _send_badsum(self, packet):
        try:
            packet.recalculate_checksums()
        except Exception:
            pass
        try:
            tcp = packet.tcp
            if tcp is not None:
                cs = tcp.checksum
                if cs is not None:
                    tcp.checksum = (cs ^ CHECKSUM_FLIP) & CHECKSUM_MASK
        except Exception:
            pass
        self._send_one(packet, recalculate=False)

    @staticmethod
    def _clone_packet(packet):
        try:
            return pydivert.Packet(bytes(packet.raw), packet.interface,
                                   packet.direction)
        except Exception:
            return copy.deepcopy(packet)

    @staticmethod
    def _conn_key(packet):
        tcp = packet.tcp
        if tcp is None:
            return None
        if packet.ipv4 is not None:
            ip = packet.ipv4
        elif packet.ipv6 is not None:
            ip = packet.ipv6
        else:
            return None
        try:
            return (ip.src_addr, tcp.src_port, ip.dst_addr, tcp.dst_port)
        except Exception:
            return None

    @staticmethod
    def _is_dst_local(packet):
        if packet.ipv4 is not None:
            return _ip_is_local(packet.ipv4.dst_addr, True)
        if packet.ipv6 is not None:
            return _ip_is_local(packet.ipv6.dst_addr, False)
        return False

    # -------- process --------

    def process(self, packet):
        if self._stop_event.is_set():
            self._send_one(packet)
            return

        if self._is_dst_local(packet):
            self._send_one(packet)
            return

        if packet.udp is not None:
            if self.cfg.block_quic:
                try:
                    if packet.udp.dst_port == PORT_HTTPS:
                        self.packets_quic_dropped += 1
                        return
                except Exception:
                    pass
            self._send_one(packet)
            return

        if not packet.tcp:
            self._send_one(packet)
            return
        if not packet.payload:
            self._send_one(packet)
            return

        payload = bytes(packet.payload)
        key = self._conn_key(packet)

        if key is not None:
            with self._pending_lock:
                has_pending = key in self._pending
            if has_pending:
                self._continue_pending(key, packet, payload)
                return

        self._dispatch_fresh(key, packet, payload)

    def _dispatch_fresh(self, key, packet, payload):
        kind, data = self._detect_host(payload)

        if kind == "match":
            host_off, hostname = data
            if self.bypass_all or self._host_matches(hostname):
                self._mark_bypassed(len(payload))
                self._fragment_and_send(packet, payload, host_off, hostname)
            else:
                self._send_one(packet)
            return

        if kind == "incomplete":
            if key is not None:
                with self._pending_lock:
                    self._pending[key] = PendingState(
                        buf=payload, ts=time.monotonic(),
                        packets=[packet], first_seq=packet.tcp.seq_num)
                return
            self._send_one(packet)
            return

        self._send_one(packet)

    def _continue_pending(self, key, packet, payload):
        action = None
        with self._pending_lock:
            state = self._pending.get(key)
            if state is None:
                action = ("fresh", key, packet, payload)
            else:
                expected_seq = (state.first_seq + len(state.buf)) & SEQ_MASK
                seq = packet.tcp.seq_num
                if seq != expected_seq:
                    delta = (seq - expected_seq) & SEQ_MASK
                    if delta > SEQ_HALF:
                        rel = (seq - state.first_seq) & SEQ_MASK
                        if rel + len(payload) <= len(state.buf):
                            return
                        action = ("send", packet)
                    else:
                        del self._pending[key]
                        action = ("flush_fresh", state, key, packet, payload)
                else:
                    combined = state.buf + payload
                    if (len(combined) > self.cfg.pending_max_bytes
                            or len(state.packets) >= self.cfg.pending_max_packets):
                        del self._pending[key]
                        action = ("flush_fresh", state, key, packet, payload)
                    else:
                        kind, data = self._detect_host(combined)
                        if kind == "match":
                            host_off, hostname = data
                            del self._pending[key]
                            if not (self.bypass_all
                                    or self._host_matches(hostname)):
                                action = ("flush_send", state, packet)
                            else:
                                action = ("fragment", state.packets[0],
                                          combined, host_off, hostname)
                        elif kind == "incomplete":
                            state.buf = combined
                            state.ts = time.monotonic()
                            state.packets.append(packet)
                            return
                        else:
                            del self._pending[key]
                            action = ("flush_fresh", state, key, packet, payload)

        if action is None:
            return
        kind = action[0]
        if kind == "send":
            self._send_one(action[1])
        elif kind == "fresh":
            self._dispatch_fresh(action[1], action[2], action[3])
        elif kind == "flush_fresh":
            _, st, k, pk, pl = action
            self._flush_as_is(st)
            self._dispatch_fresh(k, pk, pl)
        elif kind == "flush_send":
            _, st, pk = action
            self._flush_as_is(st)
            self._send_one(pk)
        elif kind == "fragment":
            _, base, combined, host_off, hostname = action
            self._mark_bypassed(len(combined))
            self._fragment_and_send(base, combined, host_off, hostname)

    def _flush_expired(self):
        if self._stop_event.is_set():
            return
        with self._pending_lock:
            if not self._pending:
                return
            now = time.monotonic()
            expired = [k for k, s in self._pending.items()
                       if now - s.ts > self.cfg.pending_timeout_s]
            states = [self._pending.pop(k) for k in expired]
        for state in states:
            self._flush_as_is(state)

    def _flush_as_is(self, state):
        for p in state.packets:
            self._send_one(p)

    # -------- parsing --------

    @staticmethod
    def _is_tls_clienthello_start(payload):
        if len(payload) < TLS_RECORD_HEADER_LEN + 1:
            return False
        if payload[0] != TLS_CONTENT_HANDSHAKE:
            return False
        if payload[5] != TLS_HANDSHAKE_CLIENT_HELLO:
            return False
        return True

    @staticmethod
    def _tls_record_incomplete(payload):
        if len(payload) < TLS_RECORD_HEADER_LEN:
            return True
        if payload[0] != TLS_CONTENT_HANDSHAKE:
            return False
        record_len = int.from_bytes(payload[3:5], "big")
        return len(payload) < TLS_RECORD_HEADER_LEN + record_len

    @staticmethod
    def _is_http_request_start(payload):
        if not payload:
            return False
        for m in HTTP_METHODS:
            if payload.startswith(m):
                nxt = payload[len(m):len(m) + 1]
                if nxt in (b" ", b"\t", b""):
                    return True
        return False

    @staticmethod
    def _is_http_request_partial(payload):
        if not payload:
            return False
        n = len(payload)
        for m in HTTP_METHODS:
            if n < len(m) and m.startswith(payload):
                return True
            if n == len(m) and m == payload:
                return True
        return False

    @staticmethod
    def _http_host(payload):
        if not payload:
            return None
        first_line_end = payload.find(CRLF)
        if first_line_end < 0:
            return None
        hdr_end = payload.find(CRLFCRLF, first_line_end)
        if hdr_end < 0:
            max_scan = min(len(payload), HTTP_HEADER_MAX_SCAN)
        else:
            max_scan = min(hdr_end, HTTP_HEADER_MAX_SCAN)
        pos = first_line_end + 2
        while pos <= max_scan:
            line_end = payload.find(CRLF, pos)
            if line_end < 0 or line_end > max_scan:
                return None
            if line_end == pos:
                return None
            if payload[pos:pos + len(HOST_HEADER)].lower() == HOST_HEADER:
                value_start = pos + len(HOST_HEADER)
                while (value_start < line_end
                       and payload[value_start:value_start + 1] in (b" ", b"\t")):
                    value_start += 1
                value_end = line_end
                while (value_end > value_start
                       and payload[value_end - 1:value_end] in (b" ", b"\t")):
                    value_end -= 1
                host_bytes = payload[value_start:value_end]
                if host_bytes.startswith(b"["):
                    close = host_bytes.find(b"]")
                    if close >= 0:
                        host_bytes = host_bytes[:close + 1]
                else:
                    sep = host_bytes.find(HOST_PORT_SEP)
                    if sep >= 0:
                        host_bytes = host_bytes[:sep]
                if not host_bytes:
                    return None
                return (value_start, bytes(host_bytes))
            pos = line_end + 2
        return None

    def _detect_host(self, payload):
        if not payload:
            return ("none", None)
        if (payload[0] == TLS_CONTENT_HANDSHAKE
                and len(payload) < TLS_RECORD_HEADER_LEN + 1):
            return ("incomplete", None)
        if self._is_tls_clienthello_start(payload):
            sni = self._tls_sni(payload)
            if sni is not None:
                return ("match", sni)
            if self._tls_record_incomplete(payload):
                return ("incomplete", None)
            return ("none", None)
        if self._is_http_request_partial(payload):
            return ("incomplete", None)
        if self._is_http_request_start(payload):
            host = self._http_host(payload)
            if host is not None:
                return ("match", host)
            if CRLFCRLF not in payload[:HTTP_HEADER_MAX_SCAN]:
                return ("incomplete", None)
            return ("none", None)
        return ("none", None)

    def _host_matches(self, host):
        h = host.lower().rstrip(b".")
        if h in self.domains:
            return True
        parts = h.split(b".")
        for i in range(1, len(parts)):
            if b".".join(parts[i:]) in self.domains:
                return True
        return False

    @staticmethod
    def _tls_sni(payload):
        if len(payload) < TLS_MIN_CLIENTHELLO_LEN:
            return None
        if payload[0] != TLS_CONTENT_HANDSHAKE:
            return None
        if payload[5] != TLS_HANDSHAKE_CLIENT_HELLO:
            return None
        record_len = int.from_bytes(payload[3:5], "big")
        record_end = TLS_RECORD_HEADER_LEN + record_len
        if record_end > len(payload):
            return None
        if record_end < TLS_MIN_CLIENTHELLO_LEN:
            return None
        pos = 9
        if pos + 2 + 32 > record_end:
            return None
        pos += 2 + 32
        if pos + 1 > record_end:
            return None
        sid_len = payload[pos]
        pos += 1 + sid_len
        if pos + 2 > record_end:
            return None
        cs_len = int.from_bytes(payload[pos:pos + 2], "big")
        pos += 2 + cs_len
        if pos + 1 > record_end:
            return None
        cm_len = payload[pos]
        pos += 1 + cm_len
        if pos + 2 > record_end:
            return None
        ext_total_len = int.from_bytes(payload[pos:pos + 2], "big")
        pos += 2
        ext_end = pos + ext_total_len
        if ext_end > record_end:
            return None
        while pos + TLS_EXT_HEADER_LEN <= ext_end:
            ext_type = int.from_bytes(payload[pos:pos + 2], "big")
            ext_len = int.from_bytes(payload[pos + 2:pos + 4], "big")
            if pos + TLS_EXT_HEADER_LEN + ext_len > ext_end:
                return None
            pos += TLS_EXT_HEADER_LEN
            if ext_type == TLS_SNI_EXT_TYPE:
                if pos + 5 > ext_end:
                    return None
                name_type = payload[pos + 2]
                name_len = int.from_bytes(payload[pos + 3:pos + 5], "big")
                host_off = pos + 5
                if name_type != 0:
                    pos += ext_len
                    continue
                if host_off + name_len > ext_end:
                    return None
                return (host_off, payload[host_off:host_off + name_len])
            pos += ext_len
        return None

    # -------- split / fragment --------

    @staticmethod
    def _midsld_offset(hostname):
        hostname = hostname.rstrip(b".")
        n = len(hostname)
        if n < 3:
            return None
        dots = [i for i, b in enumerate(hostname) if b == DOT_BYTE]
        if not dots:
            mid = n // 2
            return mid if 0 < mid < n else None
        if len(dots) == 1:
            sld_start, sld_end = 0, dots[0]
        else:
            sld_start, sld_end = dots[-2] + 1, dots[-1]
        sld_len = sld_end - sld_start
        if sld_len < 2:
            return None
        mid = sld_start + sld_len // 2
        if mid <= 0 or mid >= n:
            return None
        return mid

    def _split_offset_for_match(self, host_off, hostname):
        h = hostname.rstrip(b".")
        mode = self.cfg.split_pos
        if mode == "midsld":
            rel = self._midsld_offset(h)
            if rel is not None:
                return host_off + rel
        n = len(h)
        if n >= 2:
            return host_off + random.randint(1, n - 1)
        return host_off + max(0, n)

    def _fragment_and_send(self, packet, payload, host_off, hostname):
        split_at = self._split_offset_for_match(host_off, hostname)
        if split_at < 1:
            split_at = 1
        if split_at >= len(payload) - 1:
            self._send_whole(packet, payload)
            return
        first = payload[:split_at]
        second = payload[split_at:]
        seq = packet.tcp.seq_num
        disorder = self.mode.endswith("disorder")
        use_fake = self.mode.startswith("fake")
        try:
            if not use_fake:
                self._send_pair(packet, first, second, seq, split_at, disorder)
                return
            fake_payload = self._make_fake(payload, host_off, hostname)
            if fake_payload is None:
                self._send_pair(packet, first, second, seq, split_at, disorder)
                return
            self._send_fakes(packet, fake_payload)
            snapshot = self._clone_packet(packet)
            self._schedule(
                self.cfg.fake_split_delay_s,
                lambda: self._send_pair(snapshot, first, second, seq,
                                        split_at, disorder),
            )
        except Exception as e:
            self.log(f"frag error: {e}")
            try:
                self._send_with_checksum(packet)
            except Exception:
                pass

    def _send_whole(self, packet, payload):
        try:
            same = bytes(packet.payload) == payload
        except Exception:
            same = False
        if same:
            self._send_with_checksum(packet)
            return
        p = self._clone_packet(packet)
        p.payload = payload
        try:
            p.tcp.psh = True
        except Exception:
            pass
        self._send_with_checksum(p)

    def _send_fakes(self, packet, fake_payload):
        repeats = max(1, int(self.cfg.fake_repeats))
        for _ in range(repeats):
            fake = self._clone_packet(packet)
            fake.payload = fake_payload
            if fake.ipv4 is not None:
                fake.ipv4.ttl = self.cfg.fake_ttl
            elif fake.ipv6 is not None:
                fake.ipv6.hop_limit = self.cfg.fake_ttl
            if self.cfg.fake_badsum:
                self._send_badsum(fake)
            else:
                self._send_with_checksum(fake)

    @staticmethod
    def _fake_sni(n):
        if n <= 0:
            return None
        suffix = b".com"
        if n == len(FAKE_SNI_BASE):
            return FAKE_SNI_BASE
        if n <= len(suffix):
            return None
        if n < len(FAKE_SNI_BASE):
            return b"a" * (n - len(suffix)) + suffix
        prefix = b"www."
        return prefix + b"a" * (n - len(prefix) - len(suffix)) + suffix

    @staticmethod
    def _make_fake(payload, host_off, hostname):
        n = len(hostname)
        if n == 0:
            return None
        rep = DpiBypass._fake_sni(n)
        if rep is None or len(rep) != n:
            return None
        fake = bytearray(payload)
        fake[host_off:host_off + n] = rep
        return bytes(fake)

    def _send_pair(self, packet, first, second, seq, split_at, disorder=False):
        if disorder:
            p2 = self._clone_packet(packet)
            p2.payload = second
            p2.tcp.seq_num = (seq + split_at) & SEQ_MASK
            p2.tcp.psh = False
            self._send_with_checksum(p2)
            snapshot = self._clone_packet(packet)

            def resend_first():
                p1 = self._clone_packet(snapshot)
                p1.payload = first
                p1.tcp.seq_num = seq
                p1.tcp.psh = True
                self._send_with_checksum(p1)

            self._schedule(self.cfg.disorder_delay_s, resend_first)
        else:
            p1 = self._clone_packet(packet)
            p1.payload = first
            p1.tcp.seq_num = seq
            p1.tcp.psh = False
            self._send_with_checksum(p1)
            p2 = self._clone_packet(packet)
            p2.payload = second
            p2.tcp.seq_num = (seq + split_at) & SEQ_MASK
            p2.tcp.psh = True
            self._send_with_checksum(p2)

    # -------- lifecycle --------

    def _shutdown(self, w, pkt_queue, recv_thread):
        with self._lock:
            self._shutting_down = True
        self._stop_event.set()
        with self._pq_cond:
            self._pq_cond.notify_all()

        t = self._worker_thread
        self._worker_thread = None
        if t is not None and t.is_alive() and t is not threading.current_thread():
            t.join(timeout=RT_WORKER_JOIN_TIMEOUT_S)

        deadline = time.monotonic() + RT_SHUTDOWN_GRACE_S
        while time.monotonic() < deadline:
            remaining = []
            with self._pq_cond:
                while self._pq:
                    _, _, func = heapq.heappop(self._pq)
                    remaining.append(func)
            if not remaining:
                break
            for func in remaining:
                try:
                    func()
                except Exception:
                    pass

        with self._pending_lock:
            pending_states = list(self._pending.values())
            self._pending.clear()

        with self._lock:
            w_now = self.w
            self.w = None

        if w_now is not None:
            for state in pending_states:
                for p in state.packets:
                    with self._send_lock:
                        try:
                            w_now.send(p)
                        except Exception:
                            pass

        if w_now is not None and pkt_queue is not None:
            t_end = time.monotonic() + RT_SHUTDOWN_GRACE_S
            while time.monotonic() < t_end:
                if (recv_thread is not None and not recv_thread.is_alive()
                        and pkt_queue.empty()):
                    break
                try:
                    p = pkt_queue.get(timeout=RT_DRAIN_GET_TIMEOUT_S)
                except queue.Empty:
                    continue
                with self._send_lock:
                    try:
                        w_now.send(p)
                    except Exception:
                        pass
            while True:
                try:
                    p = pkt_queue.get_nowait()
                except queue.Empty:
                    break
                with self._send_lock:
                    try:
                        w_now.send(p)
                    except Exception:
                        pass

        with self._lock:
            self.running = False

        for sock in (w, w_now):
            if sock is not None:
                try:
                    sock.close()
                except Exception:
                    pass

        if (recv_thread is not None and recv_thread.is_alive()
                and recv_thread is not threading.current_thread()):
            recv_thread.join(timeout=RT_RECV_JOIN_TIMEOUT_S)

        if self._started:
            self.log("Остановлено")
        if self.done_cb:
            try:
                self.done_cb()
            except Exception:
                pass

    def run(self):
        pkt_queue = queue.Queue(maxsize=RT_PACKET_QUEUE_MAX)
        recv_thread = None
        w = None
        try:
            self.log(f"Запуск — режим {self.mode}"
                     f"{' (обход всего)' if self.bypass_all else ''}")
            with self._lock:
                self.running = True

            if self._stop_event.is_set():
                return
            if pydivert is None:
                self.log("ОШИБКА: pydivert не установлен")
                return

            self._worker_thread = threading.Thread(
                target=self._worker_loop, daemon=True, name="dpi-worker")
            self._worker_thread.start()

            w = pydivert.WinDivert(self.cfg.windivert_filter)
            w.open()
            with self._lock:
                self.w = w
            self._started = True

            if self._stop_event.is_set():
                return

            def _receiver():
                nonlocal w
                retries = 0
                while not self._stop_event.is_set():
                    if w is None:
                        try:
                            w = pydivert.WinDivert(self.cfg.windivert_filter)
                            w.open()
                            with self._lock:
                                if self._stop_event.is_set() or self._shutting_down:
                                    try:
                                        w.close()
                                    except Exception:
                                        pass
                                    w = None
                                    return
                                self.w = w
                            retries = 0
                        except Exception as e2:
                            retries += 1
                            if retries > 3:
                                self.log("recv: не удалось переоткрыть WinDivert")
                                return
                            if self._stop_event.wait(2.0):
                                return
                            continue
                    try:
                        p = w.recv()
                    except Exception as e:
                        if self._stop_event.is_set() or self._shutting_down:
                            return
                        self.log(f"recv: {e} — перезапуск")
                        with self._send_lock:
                            try:
                                w.close()
                            except Exception:
                                pass
                        w = None
                        with self._lock:
                            self.w = None
                        if self._stop_event.wait(2.0):
                            return
                        continue
                    if self._shutting_down:
                        self._send_one(p)
                        return
                    try:
                        pkt_queue.put(p, timeout=RT_QUEUE_PUT_TIMEOUT_S)
                    except queue.Full:
                        self._send_one(p)
                if not self._stop_event.is_set():
                    self.stop()

            recv_thread = threading.Thread(target=_receiver, daemon=True,
                                           name="dpi-recv")
            recv_thread.start()

            last_report = time.monotonic()
            while not self._stop_event.is_set():
                try:
                    packet = pkt_queue.get(timeout=RT_QUEUE_GET_TIMEOUT_S)
                except queue.Empty:
                    pass
                else:
                    try:
                        self.process(packet)
                    except Exception as e:
                        self.log(f"process error: {e}")
                        self._send_one(packet)

                now = time.monotonic()
                if now - last_report >= 5.0:
                    last_report = now
                    s = self.get_stats()
                    bw = s["bw_bps"]
                    bw_s = (f"{bw/1024/1024:.2f} МБ/с" if bw >= 1024 * 1024
                            else f"{bw/1024:.1f} КБ/с" if bw >= 1024
                            else f"{bw:.0f} Б/с")
                    self.log(
                        f"stats: пакетов={s['bypassed']:,} "
                        f"байт={s['bytes']:,} ({bw_s}) "
                        f"QUIC={s['quic_dropped']:,} "
                        f"pending={s['pending_pkts']}/{s['pending_conn']}"
                    )
        except Exception:
            self.log("КРИТИЧЕСКАЯ ОШИБКА:")
            for line in traceback.format_exc().splitlines():
                self.log("  " + line)
        finally:
            self._shutdown(w, pkt_queue, recv_thread)


# ----------------------------- CLI -----------------------------

def load_domains(args):
    domains = set() if args.no_defaults else set(DEFAULT_DOMAINS)
    if args.domains_file:
        try:
            with open(args.domains_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        domains.add(line)
        except Exception as e:
            print(f"!! не удалось прочитать {args.domains_file}: {e}")
    for d in (args.domain or []):
        domains.add(d)
    return sorted(domains)


def build_config(args):
    return replace(
        DpiConfig(),
        fake_ttl=args.ttl,
        fake_repeats=args.repeats,
        fake_badsum=not args.no_badsum,
        split_pos=args.split,
        block_quic=not args.no_block_quic,
        disorder_delay_s=args.disorder_delay,
        fake_split_delay_s=args.fake_delay,
    )


def cmd_list_modes(_args):
    print("Режимы:", ", ".join(MODES))
    print("Split: ", ", ".join(MODES_SPLIT))
    print(f"TTL:   {TTL_MIN}..{TTL_MAX}")
    print("Repeats: 1..5")
    print()
    print("Примеры:")
    print("  pydpi.py start --mode disorder")
    print("  pydpi.py start --mode fake+disorder --ttl 1 --repeats 2")
    print("  pydpi.py start --mode disorder --all")
    print("  pydpi.py test")
    print("  pydpi.py dns")


def cmd_dns(_args):
    print(f"Проверка {len(DNS_CHECK_DOMAINS)} доменов…")
    bad = []
    resolved = 0
    for d in DNS_CHECK_DOMAINS:
        try:
            ip = socket.gethostbyname(d)
        except Exception:
            continue
        resolved += 1
        try:
            if _ip_is_local(ip, True):
                bad.append((d, ip))
        except Exception:
            continue
    for d, ip in bad:
        print(f"  !! {d} -> {ip} (похоже на подмену DNS)")
    if bad:
        print(f"Найдено {len(bad)}/{resolved} подозрительных. "
              f"Смени DNS на 8.8.8.8 / 1.1.1.1")
    elif resolved == 0:
        print("Не удалось разрешить ни один домен.")
    else:
        print(f"OK: {resolved}/{len(DNS_CHECK_DOMAINS)} резолвятся нормально.")


def cmd_test(args):
    if pydivert is None:
        print("!! pydivert не установлен: pip install pydivert")
        return 2
    if not is_admin():
        print("!! Нужны права администратора.")
        return 1

    cfg = DpiConfig()
    duration = max(1, int(getattr(args, "duration", RT_TEST_DURATION_S)))
    print(f"Тест WinDivert, {duration} сек…")
    stop_ev = threading.Event()
    recv_q = queue.Queue(maxsize=RT_PACKET_QUEUE_MAX)
    n = 0
    w = None
    rt = None
    try:
        w = pydivert.WinDivert(cfg.windivert_filter)
        w.open()
        local_w = w

        def receiver():
            while not stop_ev.is_set():
                try:
                    p = local_w.recv()
                except Exception:
                    return
                try:
                    recv_q.put(p, timeout=RT_QUEUE_PUT_TIMEOUT_S)
                except queue.Full:
                    try:
                        local_w.send(p)
                    except Exception:
                        return

        rt = threading.Thread(target=receiver, daemon=True)
        rt.start()

        t0 = time.time()
        while time.time() - t0 < duration:
            if stop_ev.is_set():
                break
            try:
                p = recv_q.get(timeout=RT_QUEUE_GET_TIMEOUT_S)
            except queue.Empty:
                continue
            try:
                local_w.send(p)
                n += 1
            except Exception as e:
                print(f"send err: {e}")
                break

        stop_ev.set()

        while True:
            try:
                p = recv_q.get_nowait()
            except queue.Empty:
                break
            try:
                local_w.send(p)
                n += 1
            except Exception:
                pass
    finally:
        stop_ev.set()
        if w is not None:
            try:
                w.close()
            except Exception:
                pass
        if rt is not None and rt.is_alive():
            rt.join(timeout=RT_RECV_JOIN_TIMEOUT_S)

    print(f"Тест завершён: переслано {n} пакетов.")
    return 0


def cmd_start(args):
    if pydivert is None:
        print("!! pydivert не установлен: pip install pydivert")
        return 2
    if not is_admin():
        print("!! Нужны права администратора. Запусти от имени администратора.")
        return 1

    domains = load_domains(args)
    if not domains and not args.all:
        print("!! Список доменов пуст. Укажи --domain/--domains-file или --all.")
        return 2

    cfg = build_config(args)

    verbose = not args.quiet

    def log(msg):
        if verbose:
            ts = time.strftime("%H:%M:%S")
            print(f"[{ts}] {msg}", flush=True)

    stop = threading.Event()

    def on_signal(signum, frame):
        log("Сигнал — остановка")
        stop.set()

    try:
        signal.signal(signal.SIGINT, on_signal)
        signal.signal(signal.SIGTERM, on_signal)
    except Exception:
        pass

    engine = DpiBypass(
        domains=domains,
        mode=args.mode,
        log_cb=log,
        done_cb=lambda: stop.set(),
        config=cfg,
        bypass_all=args.all,
    )

    log(f"Доменов: {len(domains)}"
        f"{' + обход всего' if args.all else ''}")
    if args.all:
        log("⚠ РЕЖИМ: обход всего включён — может ломать "
            "отдельные сайты и замедлять трафик")
    log(f"Split: {cfg.split_pos}, TTL={cfg.fake_ttl}, "
        f"repeats={cfg.fake_repeats}, badsum={cfg.fake_badsum}, "
        f"block_quic={cfg.block_quic}")

    t = threading.Thread(target=engine.run, daemon=True, name="pydpi-main")
    t.start()

    try:
        while not stop.is_set() and t.is_alive():
            stop.wait(0.5)
    except KeyboardInterrupt:
        log("Ctrl+C — остановка")

    engine.stop()
    t.join(timeout=RT_WORKER_JOIN_TIMEOUT_S + RT_RECV_JOIN_TIMEOUT_S + 1.0)
    s = engine.get_stats()
    print(f"Итог: пакетов={s['bypassed']:,}, байт={s['bytes']:,}, "
          f"QUIC={s['quic_dropped']:,}")
    return 0


def build_parser():
    p = argparse.ArgumentParser(
        prog="pydpi",
        description="PY-DPI CLI — обход DPI-блокировок (Windows).",
    )
    p.add_argument("--version", action="version",
                   version=f"{APP_TITLE} {APP_VERSION}")
    sub = p.add_subparsers(dest="cmd", required=True)

    def add_common(sp):
        sp.add_argument("--mode", choices=MODES, default="disorder")
        sp.add_argument("--split", choices=MODES_SPLIT, default="midsld")
        sp.add_argument("--ttl", type=int, default=1,
                        choices=range(TTL_MIN, TTL_MAX + 1))
        sp.add_argument("--repeats", type=int, default=2, choices=range(1, 6))
        sp.add_argument("--no-badsum", action="store_true",
                        help="не портить контрольную сумму фейка")
        sp.add_argument("--no-block-quic", action="store_true",
                        help="не блокировать QUIC (UDP/443)")
        sp.add_argument("--disorder-delay", type=float, default=0.005,
                        help="задержка между пакетами disorder (сек)")
        sp.add_argument("--fake-delay", type=float, default=0.005,
                        help="задержка между фейком и реальным пакетом (сек)")

    sp = sub.add_parser("start", help="запустить обход")
    add_common(sp)
    sp.add_argument("--domain", action="append",
                    help="добавить домен (можно повторять)")
    sp.add_argument("--domains-file",
                    help="файл со списком доменов (по одному в строке)")
    sp.add_argument("--no-defaults", action="store_true",
                    help="не использовать встроенный список доменов")
    sp.add_argument("--all", action="store_true",
                    help="обход всех соединений (осторожно!)")
    sp.add_argument("--quiet", action="store_true",
                    help="меньше логов")
    sp.set_defaults(func=cmd_start)

    sp = sub.add_parser("test", help="тест WinDivert")
    sp.add_argument("--duration", type=int, default=RT_TEST_DURATION_S,
                    help=f"длительность теста в секундах "
                         f"(по умолчанию {RT_TEST_DURATION_S})")
    sp.set_defaults(func=cmd_test)

    sp = sub.add_parser("dns", help="проверка DNS на подмену")
    sp.set_defaults(func=cmd_dns)

    sp = sub.add_parser("list-modes", help="показать режимы и примеры")
    sp.set_defaults(func=cmd_list_modes)

    return p


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args) or 0
    except KeyboardInterrupt:
        print("\nПрервано пользователем")
        return 130


if __name__ == "__main__":
    sys.exit(main())
