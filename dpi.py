import sys
import copy
import time
import queue
import random
import heapq
import ctypes
import functools
import traceback
import threading
import tkinter as tk
import webbrowser

from dataclasses import dataclass, replace
from tkinter import ttk, scrolledtext, messagebox
from config import (APP_TITLE, APP_AUTHOR, APP_VERSION, APP_GITHUB,WINDOW_SIZE, WINDOW_MIN_SIZE,LOG_POLL_MS, STATS_POLL_MS, MAX_LOG_LINES,LOG_FONT, DOMAINS_TEXT_HEIGHT, LOG_TEXT_HEIGHT, MODE_COMBO_WIDTH,MODES, DEFAULT_MODE, MODES_SPLIT, DEFAULT_SPLIT, PORT_HTTPS, FAKE_SNI_BASE,TLS_CONTENT_HANDSHAKE, TLS_HANDSHAKE_CLIENT_HELLO, TLS_SNI_EXT_TYPE,TLS_RECORD_HEADER_LEN, TLS_EXT_HEADER_LEN, TLS_MIN_CLIENTHELLO_LEN, SEQ_MASK, SEQ_HALF, CHECKSUM_MASK, CHECKSUM_FLIP, TTL_MIN, TTL_MAX,DOT_BYTE, Config, CONFIG, DEFAULT_DOMAINS,
)

try:
    import pydivert
except ImportError:
    pydivert = None

SHUTDOWN_GRACE_S = 0.5


@dataclass
class PendingState:
    buf: bytes
    ts: float
    packets: list
    first_seq: int


def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def on_ui(func):
    @functools.wraps(func)
    def wrapper(self, *args, **kwargs):
        self.root.after(0, lambda: func(self, *args, **kwargs))
    return wrapper


def require_admin(title="Ошибка", msg="Нужны права администратора."):
    def deco(func):
        @functools.wraps(func)
        def wrapper(self, *args, **kwargs):
            if not is_admin():
                messagebox.showerror(title, msg)
                return None
            return func(self, *args, **kwargs)
        return wrapper
    return deco


class DpiBypass:

    def __init__(self, domains, mode, log_cb, done_cb=None, config=CONFIG):
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
        self.cfg = config
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self.running = False
        self.w = None
        self._pending = {}
        self._pending_lock = threading.RLock()
        self.packets_processed = 0
        self.packets_bypassed = 0
        self.packets_quic_dropped = 0

        self._pq = []
        self._pq_seq = 0
        self._pq_cond = threading.Condition(threading.Lock())
        self._worker_thread = None

    def get_stats(self):
        with self._pending_lock:
            pending_pkts = sum(len(s.packets) for s in self._pending.values())
            pending_conn = len(self._pending)
        return {
            "processed": self.packets_processed,
            "bypassed": self.packets_bypassed,
            "quic_dropped": self.packets_quic_dropped,
            "pending_pkts": pending_pkts,
            "pending_conn": pending_conn,
        }

    def _schedule(self, delay, func):
        with self._pq_cond:
            self._pq_seq += 1
            heapq.heappush(
                self._pq,
                (time.monotonic() + delay, self._pq_seq, func),
            )
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
                except Exception as e:
                    try:
                        self.log(f"delayed send err: {e}")
                    except Exception:
                        pass

            now = time.monotonic()
            if now - last_flush >= self.cfg.pending_flush_interval_s:
                last_flush = now
                try:
                    self._flush_expired()
                except Exception as e:
                    try:
                        self.log(f"flush err: {e}")
                    except Exception:
                        pass

            with self._pq_cond:
                if self._stop_event.is_set():
                    return
                wait = 0.1
                if self._pq:
                    wait = min(wait, max(0.0, self._pq[0][0] - time.monotonic()))
                if wait > 0:
                    self._pq_cond.wait(wait)

    def stop(self):
        if self._stop_event.is_set():
            return
        try:
            self.log("Останавливаю…")
        except Exception:
            pass
        self._stop_event.set()
        with self._pq_cond:
            self._pq_cond.notify_all()

    def _shutdown(self, w, pkt_queue, recv_thread):
        self._stop_event.set()
        with self._pq_cond:
            self._pq_cond.notify_all()

        t = self._worker_thread
        self._worker_thread = None
        if t is not None and t.is_alive() and t is not threading.current_thread():
            t.join(timeout=1.5)

        remaining = []
        with self._pq_cond:
            while self._pq:
                _, _, func = heapq.heappop(self._pq)
                remaining.append(func)
        for func in remaining:
            try:
                func()
            except Exception:
                pass

        if w is not None and pkt_queue is not None:
            t_end = time.monotonic() + SHUTDOWN_GRACE_S
            while time.monotonic() < t_end:
                try:
                    p = pkt_queue.get(timeout=0.05)
                except queue.Empty:
                    continue
                try:
                    w.send(p)
                except Exception:
                    pass
            while True:
                try:
                    p = pkt_queue.get_nowait()
                except queue.Empty:
                    break
                try:
                    w.send(p)
                except Exception:
                    pass

        with self._pending_lock:
            pending_states = list(self._pending.values())
            self._pending.clear()
        if w is not None:
            for state in pending_states:
                for p in state.packets:
                    try:
                        w.send(p)
                    except Exception:
                        pass

        with self._lock:
            self.running = False
            self.w = None

        if w is not None:
            try:
                w.close()
            except Exception as e:
                try:
                    self.log(f"close err: {e}")
                except Exception:
                    pass

        if (recv_thread is not None
                and recv_thread.is_alive()
                and recv_thread is not threading.current_thread()):
            recv_thread.join(timeout=1.0)

        try:
            self.log("Поток остановлен")
        except Exception:
            pass
        self._notify_done()

    @staticmethod
    def _clone_packet(packet):
        try:
            return pydivert.Packet(
                bytes(packet.raw),
                packet.interface,
                packet.direction,
            )
        except Exception:
            return copy.deepcopy(packet)

    def _send_one(self, packet):
        with self._lock:
            w = self.w
        if w is None:
            return
        try:
            w.send(packet)
        except Exception as e:
            try:
                self.log(f"send: {e}")
            except Exception:
                pass

    def _send_with_checksum(self, packet):
        try:
            packet.recalculate_checksums()
        except Exception:
            pass
        self._send_one(packet)

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
        self._send_one(packet)

    def _notify_done(self):
        if self.done_cb is None:
            return
        try:
            self.done_cb()
        except Exception as e:
            try:
                self.log(f"done_cb error: {e}")
            except Exception:
                pass

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

    def run(self):
        pkt_queue = queue.Queue(maxsize=10000)
        recv_thread = None
        w = None
        try:
            self.log("Поток запущен")
            with self._lock:
                self.running = True

            if self._stop_event.is_set():
                return

            if pydivert is None:
                self.log("ОШИБКА: pydivert не импортирован")
                return

            self._worker_thread = threading.Thread(
                target=self._worker_loop, daemon=True, name="dpi-worker")
            self._worker_thread.start()

            w = pydivert.WinDivert(self.cfg.windivert_filter)
            w.open()

            with self._lock:
                self.w = w

            if self._stop_event.is_set():
                return

            def _receiver():
                try:
                    while not self._stop_event.is_set():
                        try:
                            p = w.recv()
                        except Exception:
                            return
                        try:
                            pkt_queue.put(p, timeout=0.3)
                        except queue.Full:
                            self._send_one(p)
                finally:
                    if not self._stop_event.is_set():
                        try:
                            self.log("receiver: recv завершился, останавливаюсь")
                        except Exception:
                            pass
                        self.stop()

            recv_thread = threading.Thread(
                target=_receiver, daemon=True, name="dpi-recv")
            recv_thread.start()

            while not self._stop_event.is_set():
                try:
                    packet = pkt_queue.get(timeout=0.2)
                except queue.Empty:
                    continue
                try:
                    self.process(packet)
                except Exception as e:
                    try:
                        self.log(f"process error: {e}")
                    except Exception:
                        pass
                    self._send_one(packet)

        except Exception:
            try:
                self.log("❌ КРИТИЧЕСКАЯ ОШИБКА в потоке:")
                for line in traceback.format_exc().splitlines():
                    self.log("  " + line)
            except Exception:
                pass
        finally:
            self._shutdown(w, pkt_queue, recv_thread)

    def process(self, packet):
        if self._stop_event.is_set():
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
        if not self._is_tls_clienthello_start(payload):
            self._send_one(packet)
            return

        sni = self._tls_sni(payload)
        if sni is not None:
            self.packets_processed += 1
            host_off, hostname = sni
            if self._host_matches(hostname):
                self.packets_bypassed += 1
                self._fragment_and_send(packet, payload, host_off, hostname)
            else:
                self._send_one(packet)
            return

        if key is not None and self._tls_record_incomplete(payload):
            with self._pending_lock:
                self._pending[key] = PendingState(
                    buf=payload,
                    ts=time.monotonic(),
                    packets=[packet],
                    first_seq=packet.tcp.seq_num,
                )
            return

        self.packets_processed += 1
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
                        action = ("send", packet)
                    else:
                        del self._pending[key]
                        action = ("flush_fresh", state, key, packet, payload)
                else:
                    combined = state.buf + payload
                    if len(combined) > self.cfg.pending_max_bytes:
                        del self._pending[key]
                        action = ("flush_fresh", state, key, packet, payload)
                    else:
                        sni = self._tls_sni(combined)
                        if sni is None:
                            if self._tls_record_incomplete(combined):
                                state.buf = combined
                                state.ts = time.monotonic()
                                state.packets.append(packet)
                                return
                            del self._pending[key]
                            action = ("flush_fresh", state, key, packet, payload)
                        else:
                            host_off, hostname = sni
                            del self._pending[key]
                            if not self._host_matches(hostname):
                                action = ("flush_send", state, packet)
                            else:
                                action = ("fragment", state.packets[0], combined,
                                          host_off, hostname)

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
            self.packets_processed += 1
            self._send_one(pk)
        elif kind == "fragment":
            _, base, combined, host_off, hostname = action
            self.packets_processed += 1
            self.packets_bypassed += 1
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

        pos = 9
        pos += 2 + 32

        if pos + 1 > len(payload):
            return None
        sid_len = payload[pos]
        pos += 1 + sid_len

        if pos + 2 > len(payload):
            return None
        cs_len = int.from_bytes(payload[pos:pos + 2], "big")
        pos += 2 + cs_len

        if pos + 1 > len(payload):
            return None
        cm_len = payload[pos]
        pos += 1 + cm_len

        if pos + 2 > len(payload):
            return None
        ext_total_len = int.from_bytes(payload[pos:pos + 2], "big")
        pos += 2

        ext_end = pos + ext_total_len
        while pos + TLS_EXT_HEADER_LEN <= len(payload) and pos < ext_end:
            ext_type = int.from_bytes(payload[pos:pos + 2], "big")
            ext_len = int.from_bytes(payload[pos + 2:pos + 4], "big")
            pos += TLS_EXT_HEADER_LEN
            if ext_type == TLS_SNI_EXT_TYPE:
                if pos + 5 > len(payload):
                    return None
                name_type = payload[pos + 2]
                name_len = int.from_bytes(payload[pos + 3:pos + 5], "big")
                host_off = pos + 5
                if name_type != 0:
                    pos += ext_len
                    continue
                if host_off + name_len > len(payload):
                    return None
                return (host_off, payload[host_off:host_off + name_len])
            pos += ext_len

        return None

    @staticmethod
    def _midsld_offset(hostname):
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
        mode = self.cfg.split_pos
        if mode == "midsld":
            rel = self._midsld_offset(hostname)
            if rel is not None:
                return host_off + rel
        n = len(hostname)
        if n >= 2:
            return host_off + random.randint(1, n - 1)
        return host_off + max(0, n)

    def _fragment_and_send(self, packet, payload, host_off, hostname):
        split_at = self._split_offset_for_match(host_off, hostname)

        if split_at < 1:
            split_at = 1
        if split_at >= len(payload) - 1:
            self._send_with_checksum(packet)
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
                lambda: self._send_pair(
                    snapshot, first, second, seq, split_at, disorder),
            )
        except Exception as e:
            try:
                self.log(f"frag error: {e}")
            except Exception:
                pass
            try:
                self._send_with_checksum(packet)
            except Exception:
                pass

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
        if n < 5:
            return b"a" * n
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


class App:

    def __init__(self, root):
        self.root = root
        root.title(APP_TITLE)
        root.geometry(WINDOW_SIZE)
        root.minsize(*WINDOW_MIN_SIZE)
        root.protocol("WM_DELETE_WINDOW", self._on_close)

        self._controls_enabled = True
        self._test_running = False

        top = ttk.Frame(root, padding=8)
        top.pack(fill=tk.X)

        ttk.Label(top, text="Режим:").pack(side=tk.LEFT)
        self.mode_var = tk.StringVar(value=DEFAULT_MODE)
        self.mode_combo = ttk.Combobox(
            top, textvariable=self.mode_var,
            values=MODES, state="readonly", width=MODE_COMBO_WIDTH)
        self.mode_combo.pack(side=tk.LEFT, padx=5)

        ttk.Label(top, text="TTL фейка:").pack(side=tk.LEFT, padx=(10, 0))
        self.ttl_var = tk.StringVar(value=str(CONFIG.fake_ttl))
        self.ttl_entry = ttk.Entry(top, textvariable=self.ttl_var, width=4)
        self.ttl_entry.pack(side=tk.LEFT, padx=5)

        self.start_btn = ttk.Button(top, text="▶ Старт", command=self.toggle)
        self.start_btn.pack(side=tk.RIGHT)

        ttk.Button(top, text="Сбросить лог", command=self.clear_log
                   ).pack(side=tk.RIGHT, padx=5)

        self.test_btn = ttk.Button(top, text="Тест", command=self.test_windivert)
        self.test_btn.pack(side=tk.RIGHT, padx=5)

        ttk.Button(top, text="О программе", command=self.show_about
                   ).pack(side=tk.RIGHT, padx=5)

        opts = ttk.Frame(root, padding=(8, 0, 8, 8))
        opts.pack(fill=tk.X)

        ttk.Label(opts, text="Split:").pack(side=tk.LEFT)
        self.split_var = tk.StringVar(value=CONFIG.split_pos)
        self.split_combo = ttk.Combobox(
            opts, textvariable=self.split_var,
            values=MODES_SPLIT, state="readonly", width=8)
        self.split_combo.pack(side=tk.LEFT, padx=5)

        self.badsum_var = tk.BooleanVar(value=CONFIG.fake_badsum)
        self.badsum_chk = ttk.Checkbutton(
            opts, text="битая сумма фейка", variable=self.badsum_var)
        self.badsum_chk.pack(side=tk.LEFT, padx=(10, 0))

        mid = ttk.LabelFrame(root, text="Домены", padding=5)
        mid.pack(fill=tk.X, padx=8, pady=5)
        self.domains_text = tk.Text(mid, height=DOMAINS_TEXT_HEIGHT, wrap="none",
                                    state=tk.DISABLED, bg="#f0f0f0")
        self.domains_text.pack(fill=tk.X)

        bot = ttk.LabelFrame(root, text="Лог", padding=5)
        bot.pack(fill=tk.BOTH, expand=True, padx=8, pady=5)
        self.log_text = scrolledtext.ScrolledText(
            bot, height=LOG_TEXT_HEIGHT, state=tk.DISABLED, font=LOG_FONT)
        self.log_text.pack(fill=tk.BOTH, expand=True)

        self.status = tk.StringVar(value="Готов")
        ttk.Label(root, textvariable=self.status, relief=tk.SUNKEN,
                  anchor="w").pack(fill=tk.X, side=tk.BOTTOM)

        self.stats_line = tk.StringVar(value="")
        ttk.Label(root, textvariable=self.stats_line, relief=tk.SUNKEN,
                  anchor="w", font=LOG_FONT).pack(fill=tk.X, side=tk.BOTTOM)

        self.log_queue = queue.Queue()
        self.bypass = None
        self.thread = None

        self.mode_var.trace_add("write", lambda *_: self._sync_mode_state())

        self.root.after(LOG_POLL_MS, self._pump_log)
        self.root.after(STATS_POLL_MS, self._update_stats)

        self.log(f"Python: {sys.version.split()[0]}")
        if is_admin():
            self.log("Админ права: ДА")
        else:
            self.log("Админ права: НЕТ ⚠ — запуск обхода будет недоступен")
        if pydivert is None:
            self.log("⚠ pydivert НЕ УСТАНОВЛЕН. Выполни: pip install pydivert")
        else:
            self.log("pydivert: OK")

        self.fill_domains()
        self._sync_mode_state()

    def show_about(self):
        win = tk.Toplevel(self.root)
        win.title(f"О программе — {APP_TITLE}")
        win.transient(self.root)
        win.resizable(False, False)
        win.grab_set()

        frame = ttk.Frame(win, padding=16)
        frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(
            frame, text=APP_TITLE,
            font=("Segoe UI", 16, "bold"),
        ).pack(anchor="w")

        ttk.Label(
            frame, text=f"Версия: {APP_VERSION}",
        ).pack(anchor="w", pady=(6, 0))

        ttk.Label(
            frame, text=f"Автор: {APP_AUTHOR}",
        ).pack(anchor="w")

        link_row = ttk.Frame(frame)
        link_row.pack(anchor="w", pady=(10, 0))
        ttk.Label(link_row, text="GitHub: ").pack(side=tk.LEFT)

        link = tk.Label(
            link_row, text=APP_GITHUB,
            fg="#0066cc", cursor="hand2",
            font=("Segoe UI", 9, "underline"),
        )
        link.pack(side=tk.LEFT)

        def _open(_event=None):
            try:
                webbrowser.open(APP_GITHUB)
            except Exception as e:
                messagebox.showerror(
                    "Ошибка", f"Не удалось открыть ссылку:\n{e}")

        link.bind("<Button-1>", _open)
        link.bind("<Enter>", lambda e: link.config(fg="#004499"))
        link.bind("<Leave>", lambda e: link.config(fg="#0066cc"))

        ttk.Separator(frame, orient="horizontal").pack(
            fill=tk.X, pady=12)

        ttk.Button(frame, text="Закрыть", command=win.destroy
                   ).pack(anchor="e")

        win.update_idletasks()
        px = self.root.winfo_rootx() + (self.root.winfo_width() - win.winfo_width()) // 2
        py = self.root.winfo_rooty() + (self.root.winfo_height() - win.winfo_height()) // 2
        win.geometry(f"+{max(px, 0)}+{max(py, 0)}")

        win.bind("<Escape>", lambda e: win.destroy())

    def _set_controls_enabled(self, enabled):
        self._controls_enabled = enabled
        self.mode_combo.config(state="readonly" if enabled else tk.DISABLED)
        self.test_btn.config(state=tk.NORMAL if enabled else tk.DISABLED)
        self.split_combo.config(state="readonly" if enabled else tk.DISABLED)
        self._sync_mode_state()

    def _sync_mode_state(self):
        if not self._controls_enabled:
            self.ttl_entry.config(state=tk.DISABLED)
            self.badsum_chk.config(state=tk.DISABLED)
            return

        mode = self.mode_var.get()
        fake = mode.startswith("fake")

        self.ttl_entry.config(state=tk.NORMAL if fake else tk.DISABLED)
        self.badsum_chk.config(state=tk.NORMAL if fake else tk.DISABLED)

    def _on_close(self):
        try:
            if self.bypass is not None and self.bypass.running:
                self._stop_bypass()
        except Exception:
            pass
        try:
            self.root.destroy()
        except Exception:
            pass

    def log(self, msg):
        self.log_queue.put(str(msg))

    def clear_log(self):
        self.log_text.config(state=tk.NORMAL)
        self.log_text.delete("1.0", tk.END)
        self.log_text.config(state=tk.DISABLED)

    def _pump_log(self):
        try:
            added = False
            while not self.log_queue.empty():
                msg = self.log_queue.get()
                self.log_text.config(state=tk.NORMAL)
                self.log_text.insert(tk.END, f"[{time.strftime('%H:%M:%S')}] {msg}\n")
                added = True

            if added:
                total = int(self.log_text.index("end-1c").split(".")[0])
                if total > MAX_LOG_LINES:
                    self.log_text.delete(
                        "1.0", f"{total - MAX_LOG_LINES + 1}.0")
                self.log_text.see(tk.END)
                self.log_text.config(state=tk.DISABLED)
        finally:
            try:
                self.root.after(LOG_POLL_MS, self._pump_log)
            except tk.TclError:
                pass

    def _update_stats(self):
        try:
            b = self.bypass
            if b is not None and b.running:
                s = b.get_stats()
                self.stats_line.set(
                    f"обработано: {s['processed']:,} | "
                    f"обойдено: {s['bypassed']:,} | "
                    f"QUIC drop: {s['quic_dropped']:,} | "
                    f"pending: {s['pending_pkts']} пак. / {s['pending_conn']} соед."
                )
            else:
                self.stats_line.set("")
        finally:
            try:
                self.root.after(STATS_POLL_MS, self._update_stats)
            except tk.TclError:
                pass

    @require_admin(title="Тест", msg="Нужны права администратора.")
    def test_windivert(self):
        if pydivert is None:
            messagebox.showerror("Тест", "pip install pydivert")
            return

        if self.bypass is not None and self.bypass.running:
            messagebox.showinfo("Тест", "Сначала останови обход.")
            return

        if self._test_running:
            return

        self._test_running = True
        self._set_controls_enabled(False)

        def worker():
            self.log("— ТЕСТ: открываю WinDivert —")
            w = None
            stop_ev = threading.Event()
            recv_q = queue.Queue(maxsize=5000)
            n = 0
            rt = None
            try:
                w = pydivert.WinDivert(CONFIG.windivert_test_filter)
                w.open()
                self.log("WinDivert открыт. Считаю 5 сек…")

                def receiver():
                    while not stop_ev.is_set():
                        try:
                            p = w.recv()
                        except Exception:
                            return
                        try:
                            recv_q.put(p, timeout=0.3)
                        except queue.Full:
                            try:
                                w.send(p)
                            except Exception:
                                return

                rt = threading.Thread(target=receiver, daemon=True)
                rt.start()

                t0 = time.time()
                while time.time() - t0 < CONFIG.test_duration_s:
                    try:
                        p = recv_q.get(timeout=0.2)
                    except queue.Empty:
                        continue
                    try:
                        w.send(p)
                        n += 1
                    except Exception as e:
                        self.log(f"send err: {e}")
                        break

                stop_ev.set()
                while True:
                    try:
                        p = recv_q.get_nowait()
                    except queue.Empty:
                        break
                    try:
                        w.send(p)
                        n += 1
                    except Exception:
                        pass

                try:
                    w.close()
                except Exception:
                    pass
                w = None
                if rt is not None and rt.is_alive():
                    rt.join(timeout=1.0)

                self.log(f"— ТЕСТ завершён: поймано {n} пакетов —")
            except Exception:
                for line in traceback.format_exc().splitlines():
                    self.log("  " + line)
            finally:
                stop_ev.set()
                if w is not None:
                    try:
                        w.close()
                    except Exception:
                        pass
                self._on_test_done()

        threading.Thread(target=worker, daemon=True).start()

    @on_ui
    def _on_test_done(self):
        self._test_running = False
        if self.bypass is None or not self.bypass.running:
            self._set_controls_enabled(True)

    def toggle(self):
        if self.bypass is not None and self.bypass.running:
            self._stop_bypass()
            return

        if not is_admin():
            messagebox.showerror(
                "Ошибка",
                "Нужны права администратора.\n\n"
                "Запусти PY-DPI от имени администратора "
                "(ПКМ по ярлыку → «Запуск от имени администратора»).",
            )
            return

        if self._test_running:
            messagebox.showinfo("Старт", "Дождись окончания теста.")
            return

        if pydivert is None:
            messagebox.showerror("Ошибка", "pip install pydivert")
            return

        if self.thread is not None and self.thread.is_alive():
            self.thread.join(timeout=1.0)

        domains = [d.strip() for d in
                   self.domains_text.get("1.0", tk.END).splitlines()
                   if d.strip()]
        if not domains:
            messagebox.showerror("Ошибка", "Список доменов пуст.")
            return

        mode = self.mode_var.get()

        try:
            ttl = int(self.ttl_var.get())
            if not TTL_MIN <= ttl <= TTL_MAX:
                raise ValueError
        except ValueError:
            if mode.startswith("fake"):
                messagebox.showerror(
                    "Ошибка", f"TTL должен быть числом {TTL_MIN}..{TTL_MAX}")
                return
            ttl = CONFIG.fake_ttl

        split_pos = self.split_var.get()
        if split_pos not in MODES_SPLIT:
            split_pos = CONFIG.split_pos

        cfg = replace(
            CONFIG,
            fake_ttl=ttl,
            fake_badsum=bool(self.badsum_var.get()),
            split_pos=split_pos,
        )

        self.status.set("Запускаю…")
        self.start_btn.config(text="■ Стоп")

        self.bypass = DpiBypass(
            domains=domains,
            mode=mode,
            log_cb=self.log,
            done_cb=self._on_bypass_done,
            config=cfg,
        )

        self.thread = threading.Thread(target=self.bypass.run, daemon=True)
        self.thread.start()

        self._set_controls_enabled(False)
        self.status.set(f"Работаю — режим {mode}")

    def _reset_ui(self):
        self.stats_line.set("")
        self.start_btn.config(text="▶ Старт")
        self.status.set("Остановлено")
        self._set_controls_enabled(True)

    def _stop_bypass(self):
        b = self.bypass
        t = self.thread

        if b is not None:
            b.stop()

        if (t is not None and t.is_alive()
                and t is not threading.current_thread()):
            t.join(timeout=2.5)

        self.bypass = None
        self.thread = None
        self._reset_ui()

    @on_ui
    def _on_bypass_done(self):
        if self.bypass is None or not self.bypass.running:
            self._reset_ui()

    def fill_domains(self):
        self.domains_text.config(state=tk.NORMAL)
        self.domains_text.delete("1.0", tk.END)
        self.domains_text.insert("1.0", "\n".join(DEFAULT_DOMAINS))
        self.domains_text.config(state=tk.DISABLED)