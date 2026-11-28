import copy
import functools
import heapq
import ipaddress
import queue
import random
import threading
import time
import traceback
from collections import deque
from dataclasses import dataclass

from config import (
    _HTTP_METHOD_MAX_LEN,
    _PAYLOAD_FIRST_BYTES,
    _U16,
    BADSUM_FALLBACK,
    BADSUM_XOR_MAX,
    BADSUM_XOR_MIN,
    BW_WINDOW_S,
    CONFIG,
    CRLF,
    CRLFCRLF,
    DOT_BYTE,
    HOST_HEADER,
    HOST_PORT_SEP,
    HTTP_HEADER_MAX_SCAN,
    HTTP_METHODS,
    IP_WHITELIST_V4,
    IP_WHITELIST_V6,
    PORT_HTTPS,
    RT,
    SEQ_HALF,
    SEQ_MASK,
    TLS_CLIENT_HELLO_RANDOM_LEN,
    TLS_CLIENT_HELLO_VERSION_LEN,
    TLS_CONTENT_HANDSHAKE,
    TLS_ECH_EXT_TYPE,
    TLS_EXT_HEADER_LEN,
    TLS_HANDSHAKE_CLIENT_HELLO,
    TLS_HANDSHAKE_HEADER_LEN,
    TLS_MIN_CLIENTHELLO_LEN,
    TLS_RECORD_HEADER_LEN,
    TLS_SNI_EXT_TYPE,
)

try:
    import pydivert
except ImportError:
    pydivert = None


# Компилируем белые списки подсетей один раз при старте
_WHITELIST_V4_NETS = tuple(
    ipaddress.ip_network(c) for c in IP_WHITELIST_V4
)
_WHITELIST_V6_NETS = tuple(
    ipaddress.ip_network(c) for c in IP_WHITELIST_V6
)


@functools.lru_cache(maxsize=RT.ip_cache_size)
def _ip_is_local(s: str, is_v4: bool) -> bool:
    """Проверяет, является ли IP локальным (с кэшированием для скорости)."""
    nets = _WHITELIST_V4_NETS if is_v4 else _WHITELIST_V6_NETS
    try:
        addr = ipaddress.ip_address(s)
    except Exception:
        # Не смогли распарсить — считаем локальным, чтобы не обходить.
        return True
    for net in nets:
        if addr in net:
            return True
    return False


@dataclass(slots=True)
class PendingState:
    """Буфер для склейки пакетов, когда ClientHello/HTTP-заголовок разбит."""
    buf: bytes
    ts: float
    packets: list
    first_seq: int


class DpiBypass:
    """Основной движок обхода DPI (для GUI-версии)."""

    def __init__(self, domains, mode, log_cb, done_cb=None, config=CONFIG,
                bypass_all=False):
        self.domains = set()
        for d in domains:
            d = d.strip().lower().rstrip(".")
            if not d:
                continue
            try:
                b = d.encode("idna")  # Поддержка кириллических доменов
            except Exception:
                b = d.encode("ascii", "ignore")
            if b:
                self.domains.add(b)

        self.mode = mode
        self.log = log_cb
        self.done_cb = done_cb
        self.cfg = config
        self.bypass_all = bool(bypass_all)
        
        # Блокировки и флаги состояния
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._shutting_down = False
        self._started = False
        self.running = False
        self.w = None
        self._send_has_recalc = None
        self._send_lock = threading.Lock()
        
        self._ech_logged = False  # Флаг для предотвращения спама ECH в лог

        # Буферы для ожидания продолжения пакетов
        self._pending = {}
        self._pending_lock = threading.RLock()
        
        # Статистика
        self.packets_bypassed = 0
        self.packets_quic_dropped = 0
        self.bytes_bypassed = 0
        self._bw = deque()
        self._bw_lock = threading.Lock()

        # Очередь отложенных задач (для задержки в disorder и таймаутов)
        self._pq = []
        self._pq_seq = 0
        self._pq_cond = threading.Condition(threading.Lock())
        self._worker_thread = None

    def get_stats(self):
        """Возвращает текущую статистику для отрисовки в GUI."""
        with self._pending_lock:
            pending_pkts = sum(len(s.packets) for s in self._pending.values())
            pending_conn = len(self._pending)
        
        now = time.monotonic()
        with self._bw_lock:
            # Скользящее окно для оценки текущей скорости
            while self._bw and now - self._bw[0][0] > BW_WINDOW_S:
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
        """Увеличивает счетчики обойденных пакетов."""
        self.packets_bypassed += 1
        self.bytes_bypassed += nbytes
        with self._bw_lock:
            self._bw.append((time.monotonic(), nbytes))

    def _schedule(self, delay, func):
        """Добавляет задачу в очередь с задержкой (min-heap)."""
        with self._pq_cond:
            self._pq_seq += 1
            heapq.heappush(
                self._pq,
                (time.monotonic() + delay, self._pq_seq, func),
            )
            self._pq_cond.notify()

    def _worker_loop(self):
        """Фоновый поток для выполнения отложенных задач (задержки) и очистки таймаутов."""
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

            # Периодическая очистка зависших pending-пакетов
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
                now2 = time.monotonic()
                if self._pq:
                    wait = max(0.0, self._pq[0][0] - now2)
                else:
                    wait = self.cfg.pending_flush_interval_s
                next_flush = last_flush + self.cfg.pending_flush_interval_s
                wait = min(wait, max(0.0, next_flush - now2))
                self._pq_cond.wait(max(wait, RT.worker_min_wait_s))

    def stop(self):
        """Подает сигнал остановки всем потокам."""
        if self._stop_event.is_set():
            return
        self._stop_event.set()
        with self._pq_cond:
            self._pq_cond.notify_all()

    def _shutdown(self, w, pkt_queue, recv_thread):
        """Корректная остановка всех потоков, дренаж очередей и закрытие WinDivert."""
        with self._lock:
            self._shutting_down = True
        self._stop_event.set()
        with self._pq_cond:
            self._pq_cond.notify_all()

        t = self._worker_thread
        self._worker_thread = None
        if t is not None and t.is_alive() and t is not threading.current_thread():
            t.join(timeout=RT.worker_join_timeout_s)

        # Дожимаем все отложенные задачи (resend_first и т.п.)
        drain_deadline = time.monotonic() + RT.shutdown_grace_s
        while time.monotonic() < drain_deadline:
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
            time.sleep(0.001)  # отдаём CPU, если задача перепланировала новую
            
        with self._pending_lock:
            pending_states = list(self._pending.values())
            self._pending.clear()

        with self._lock:
            w_now = self.w
            # self.w = None здесь НЕ обнуляем — иначе _send_one в recv_thread
            # молча дропнет последние пакеты во время дренажа.

        # Отправляем всё, что осталось в буфере pending
        if w_now is not None:
            for state in pending_states:
                for p in state.packets:
                    with self._send_lock:
                        try:
                            w_now.send(p)
                        except Exception:
                            pass

        # Дренаж pkt_queue: забираем всё, что recv_thread ещё не отдал
        if w_now is not None and pkt_queue is not None:
            t_end = time.monotonic() + RT.shutdown_grace_s
            while time.monotonic() < t_end:
                if (recv_thread is not None
                        and not recv_thread.is_alive()
                        and pkt_queue.empty()):
                    break
                try:
                    p = pkt_queue.get(timeout=RT.drain_get_timeout_s)
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

        if w is not None:
            try:
                w.close()
            except Exception:
                pass

        if w_now is not None and w_now is not w:
            try:
                w_now.close()
            except Exception:
                pass

        if (recv_thread is not None
                and recv_thread.is_alive()
                and recv_thread is not threading.current_thread()):
            recv_thread.join(timeout=RT.recv_join_timeout_s)

        # Только теперь, когда все хендлы закрыты и recv_thread мёртв,
        # обнуляем self.w — никакой _send_one уже не выполнится.
        with self._lock:
            self.w = None

        if self._started:
            self.log("Поток остановлен")
        self._notify_done()

    @staticmethod
    def _clone_packet(packet):
        """Создает глубокую копию пакета (для модификации без порчи оригинала)."""
        try:
            return pydivert.Packet(
                bytes(packet.raw),
                packet.interface,
                packet.direction,
            )
        except Exception:
            return copy.deepcopy(packet)

    def _send_one(self, packet):
        """Отправляет один пакет, с проверкой версии pydivert (recalculate_checksum)."""
        with self._lock:
            w = self.w
        if w is None:
            return
        with self._send_lock:
            state = self._send_has_recalc

            if state is False:
                try:
                    w.send(packet)
                except Exception:
                    pass
                return

            # Пытаемся отправить без пересчета чексуммы (быстрее)
            try:
                w.send(packet, recalculate_checksum=False)
                if state is None:
                    self._send_has_recalc = True
                return
            except TypeError:
                pass
            except Exception:
                return

            try:
                w.send(packet)
            except Exception:
                return

            if state is None:
                self._send_has_recalc = False
                if self._started:
                    self.log("send: старая версия pydivert, работаю в совместимом режиме, рекомендовано (pip install --upgrade pydivert)")

    def _send_with_checksum(self, packet):
        """Пересчитывает контрольные суммы и отправляет пакет."""
        try:
            packet.recalculate_checksums()
        except Exception:
            pass
        self._send_one(packet)

    def _send_badsum(self, packet):
        """Намеренно портит контрольную сумму (для фейк-пакетов)."""
        try:
            packet.recalculate_checksums()
        except Exception:
            pass
        try:
            tcp = packet.tcp
            if tcp is not None:
                cs = tcp.checksum
                if cs is not None:
                    # XOR со случайным числом делает чексумму невалидной
                    new_cs = cs ^ random.randint(BADSUM_XOR_MIN, BADSUM_XOR_MAX)
                    if new_cs == 0:
                        new_cs = BADSUM_FALLBACK
                    tcp.checksum = new_cs
        except Exception:
            pass
        self._send_one(packet)

    def _notify_done(self):
        """Вызывает колбэк завершения (для GUI)."""
        if self.done_cb is None:
            return
        try:
            self.done_cb()
        except Exception:
            pass

    @staticmethod
    def _conn_key(packet):
        """Возвращает уникальный ключ соединения (src_ip, src_port, dst_ip, dst_port)."""
        tcp = packet.tcp
        if tcp is None:
            return None
        if packet.ipv4 is not None:
            ip = packet.ipv4
        elif packet.ipv6 is not None:
            ip = packet.ipv6
        else:
            return None
        return (ip.src_addr, tcp.src_port, ip.dst_addr, tcp.dst_port)

    @staticmethod
    def _is_dst_local(packet) -> bool:
        """Проверяет, не отправляется ли пакет в локальную сеть (белый список)."""
        if packet.ipv4 is not None:
            return _ip_is_local(packet.ipv4.dst_addr, True)
        if packet.ipv6 is not None:
            return _ip_is_local(packet.ipv6.dst_addr, False)
        return False

    def run(self):
        """Главный цикл движка: запускает потоки чтения, обработки и очистки."""
        pkt_queue = queue.Queue(maxsize=RT.packet_queue_maxsize)
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

            # Запускаем фоновый поток для отложенных задач
            self._worker_thread = threading.Thread(
                target=self._worker_loop, daemon=True, name="dpi-worker")
            self._worker_thread.start()

            # Открываем драйвер
            w = pydivert.WinDivert(self.cfg.windivert_filter)
            w.open()

            with self._lock:
                self.w = w

            self._started = True

            if self._stop_event.is_set():
                return

            def _receiver():
                """Поток приема пакетов от драйвера."""
                try:
                    while not self._stop_event.is_set():
                        try:
                            p = w.recv()
                        except Exception as e:
                            if (self._stop_event.is_set()
                                    or self._shutting_down):
                                return
                            self.log(f"recv: критическая ошибка WinDivert: {e}")
                            self.stop()
                            return

                        if self._shutting_down:
                            self._send_one(p)
                            return
                        try:
                            pkt_queue.put(p, timeout=RT.queue_put_timeout_s)
                        except queue.Full:
                            self._send_one(p)
                finally:
                    if not self._stop_event.is_set():
                        self.stop()

            recv_thread = threading.Thread(
                target=_receiver, daemon=True, name="dpi-recv")
            recv_thread.start()

            # Главный цикл обработки
            while not self._stop_event.is_set():
                try:
                    packet = pkt_queue.get(timeout=RT.queue_get_timeout_s)
                except queue.Empty:
                    continue
                try:
                    self.process(packet)
                except Exception as e:
                    self.log(f"process error: {e}")
                    self._send_one(packet)

        except Exception:
            self.log("❌ КРИТИЧЕСКАЯ ОШИБКА в потоке:")
            for line in traceback.format_exc().splitlines():
                self.log("  " + line)
        finally:
            self._shutdown(w, pkt_queue, recv_thread)

    def process(self, packet):
        """Обрабатывает каждый перехваченный пакет (проверка типа, IP, SNI)."""
        if self._stop_event.is_set():
            self._send_one(packet)
            return

        if packet.tcp is None:
            # Блокируем UDP/443 (QUIC), чтобы браузер перешел на TCP
            if packet.udp is not None and self.cfg.block_quic:  # noqa: SIM102
                if not self._is_dst_local(packet):
                    try:
                        if packet.udp.dst_port == PORT_HTTPS:
                            self.packets_quic_dropped += 1
                            return
                    except Exception:
                        pass
            self._send_one(packet)
            return

        payload = packet.payload
        if not payload:
            self._send_one(packet)
            return

        if self._is_dst_local(packet):
            self._send_one(packet)
            return

        key = self._conn_key(packet)

        # СНАЧАЛА проверяем pending
        if key is not None:
            with self._pending_lock:
                has_pending = key in self._pending
            if has_pending:
                self._continue_pending(key, packet, payload)
                return

        # И только ТЕПЕРЬ проверяем первый байт
        if payload[0] not in _PAYLOAD_FIRST_BYTES:
            self._send_one(packet)
            return

        self._dispatch_fresh(key, packet, payload)

    def _dispatch_fresh(self, key, packet, payload):
        """Обрабатывает первый пакет нового соединения."""
        kind, data = self._detect_host(payload)

        if kind == "match":
            host_off, hostname = data
            if self.bypass_all or self._host_matches(hostname):
                self._fragment_and_send(packet, payload, host_off, hostname)
            else:
                self._send_one(packet)
            return

        if kind == "ech":
            if data is not None:
                host_off, hostname = data
                # Проверяем, нужно ли вообще обходить этот сайт
                if self.bypass_all or self._host_matches(hostname):
                    if not self._ech_logged:
                        outer = hostname.decode("ascii", "replace")
                        self.log(
                            f"⚠ ECH: outer SNI = {outer!r}. "
                            f"Режем outer SNI, чтобы DPI не блокировал."
                        )
                        self._ech_logged = True
                    
                    self._fragment_and_send(packet, payload, host_off, hostname)
                    return
                # Если сайта нет в списке — просто тихо пропускаем
            # Если data is None (outer SNI нет) — тоже тихо пропускаем
            self._send_one(packet)
            return
        
        if kind == "incomplete":
            # Пакет обрезан — сохраняем в буфер и ждем продолжения
            if key is not None:
                with self._pending_lock:
                    self._pending[key] = PendingState(
                        buf=payload,
                        ts=time.monotonic(),
                        packets=[packet],
                        first_seq=packet.tcp.seq_num,
                    )
                return
            self._send_one(packet)
            return

        self._send_one(packet)

    def _continue_pending(self, key, packet, payload):
        """Обрабатывает пакеты, для которых уже есть буфер (склейка SNI)."""
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
                        # Ретрансмит (дубликат) — игнорируем или шлем как есть
                        rel = (seq - state.first_seq) & SEQ_MASK
                        if rel + len(payload) <= len(state.buf):
                            return
                        action = ("send", packet)
                    else:
                        # Разрыв последовательности (flush)
                        del self._pending[key]
                        action = ("flush_fresh", state, key, packet, payload)
                else:
                    combined = state.buf + payload
                    if (len(combined) > self.cfg.pending_max_bytes
                            or len(state.packets) >= self.cfg.pending_max_packets):
                        # Переполнение буфера
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
                                # SNI размазан по пакетам. Склеиваем и режем заново,
                                # чтобы DPI не увидел SNI целиком.
                                action = ("fragment_combined", state, combined, host_off, hostname)
                                
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

        match action:
            case ("send", p):
                self._send_one(p)
            case ("fresh", k, p, pl):
                self._dispatch_fresh(k, p, pl)
            case ("flush_fresh", st, k, pk, pl):
                self._flush_as_is(st)
                self._dispatch_fresh(k, pk, pl)
            case ("flush_send", st, pk):
                self._flush_as_is(st)
                self._send_one(pk)
            case ("flush_as_is_and_send", st, pk):
                self._flush_as_is(st)
                self._send_one(pk)
            case ("fragment_combined", st, comb, h_off, h_name):
                # Берем копию первого пакета, подменяем payload на склеенный
                p = self._clone_packet(st.packets[0])
                p.payload = comb
                self._fragment_and_send(p, comb, h_off, h_name)

    def _flush_expired(self):
        """Удаляет из буфера пакеты, не дождавшиеся продолжения (по таймауту)."""
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
        """Отправляет все пакеты из буфера без модификаций."""
        for p in state.packets:
            self._send_one(p)

    @staticmethod
    def _is_tls_clienthello_start(payload):
        """Проверяет, что пакет начинается с TLS ClientHello."""
        if len(payload) < TLS_RECORD_HEADER_LEN + 1:
            return False
        if payload[0] != TLS_CONTENT_HANDSHAKE:
            return False
        return payload[5] == TLS_HANDSHAKE_CLIENT_HELLO

    @staticmethod
    def _tls_record_incomplete(payload):
        """Проверяет, не обрезан ли TLS-пакет (сравнивая длины)."""
        if len(payload) < TLS_RECORD_HEADER_LEN:
            return True
        if payload[0] != TLS_CONTENT_HANDSHAKE:
            return False
        record_len = _U16.unpack_from(payload, 3)[0]
        return len(payload) < TLS_RECORD_HEADER_LEN + record_len

    @staticmethod
    def _is_http_request_start(payload):
        """Проверяет, что пакет — начало HTTP-запроса (GET, POST и т.д.)."""
        if not payload:
            return False
        for method in HTTP_METHODS:
            if payload.startswith(method):
                nxt = payload[len(method):len(method) + 1]
                if nxt in (b" ", b"\t", b""):
                    return True
        return False

    @staticmethod
    def _is_http_request_partial(payload):
        """Проверяет, является ли пакет частью HTTP-метода (например, только 'GE' от 'GET')."""
        if not payload:
            return False
        if len(payload) > _HTTP_METHOD_MAX_LEN:
            return False
        for m in HTTP_METHODS:
            if m.startswith(payload):
                return True
        return False

    @staticmethod
    def _http_host(payload):
        """Извлекает заголовок Host из HTTP-запроса."""
        if not payload:
            return None

        first_line_end = payload.find(CRLF)
        if first_line_end < 0:
            return None

        hdr_end = payload.find(CRLFCRLF, first_line_end,
                            first_line_end + HTTP_HEADER_MAX_SCAN)
        if hdr_end < 0:
            hdr_end = min(len(payload),
                        first_line_end + HTTP_HEADER_MAX_SCAN)

        pos = first_line_end + 2

        while pos <= hdr_end:
            line_end = payload.find(CRLF, pos)
            if line_end < 0 or line_end > hdr_end:
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
                    # IPv6-литерал (отрезаем порт)
                    close = host_bytes.find(b"]")
                    if close >= 0:
                        host_bytes = host_bytes[:close + 1]
                else:
                    # Отрезаем порт, если есть
                    sep = host_bytes.find(HOST_PORT_SEP)
                    if sep >= 0:
                        host_bytes = host_bytes[:sep]

                if not host_bytes:
                    return None
                return (value_start, host_bytes)

            pos = line_end + 2

        return None

    def _detect_host(self, payload):
        """Определяет тип пакета и извлекает домен (SNI/Host)."""
        if not payload:
            return ("none", None)
        if payload[0] == TLS_CONTENT_HANDSHAKE:
            return self._detect_tls(payload)
        if (self._is_http_request_start(payload)
                or self._is_http_request_partial(payload)):
            return self._detect_http(payload)
        return ("none", None)

    def _detect_tls(self, payload):
        """Парсит TLS-пакет, возвращая SNI или флаг ECH."""
        if len(payload) < TLS_RECORD_HEADER_LEN + 1:
            return ("incomplete", None)
        if not self._is_tls_clienthello_start(payload):
            return ("none", None)
        sni = self._tls_sni(payload)
        if sni is not None:
            if sni[0] == "ech":        
                return ("ech", sni[1])
            return ("match", sni)
        if self._tls_record_incomplete(payload):
            return ("incomplete", None)
        return ("none", None)

    def _detect_http(self, payload):
        """Парсит HTTP-пакет, возвращая заголовок Host."""
        if self._is_http_request_partial(payload):
            return ("incomplete", None)
        if not self._is_http_request_start(payload):
            return ("none", None)
        host = self._http_host(payload)
        if host is not None:
            return ("match", host)
        first_line_end = payload.find(CRLF)
        if first_line_end < 0:
            return ("none", None)
        if payload.find(CRLFCRLF, first_line_end,
                        first_line_end + HTTP_HEADER_MAX_SCAN) < 0:
            return ("incomplete", None)
        return ("none", None)

    def _host_matches(self, host):
        """Проверяет, есть ли домен (или поддомен) в списке обхода."""
        domains = self.domains
        if host in domains:
            return True
        h = host.rstrip(b".").lower()
        if h in domains:
            return True
        # Проверяем суффиксы (a.b.com -> b.com -> com)
        idx = h.find(b".")
        while idx >= 0:
            if h[idx + 1:] in domains:
                return True
            idx = h.find(b".", idx + 1)
        return False

    @staticmethod
    def _tls_sni(payload):
        """Извлекает SNI из TLS ClientHello или определяет наличие ECH."""
        if len(payload) < TLS_MIN_CLIENTHELLO_LEN:
            return None
        if payload[0] != TLS_CONTENT_HANDSHAKE:
            return None
        if payload[5] != TLS_HANDSHAKE_CLIENT_HELLO:
            return None

        
        pos = TLS_RECORD_HEADER_LEN + TLS_HANDSHAKE_HEADER_LEN
        if pos + TLS_CLIENT_HELLO_VERSION_LEN + TLS_CLIENT_HELLO_RANDOM_LEN > len(payload):
            return None
        pos += TLS_CLIENT_HELLO_VERSION_LEN + TLS_CLIENT_HELLO_RANDOM_LEN

        if pos + 1 > len(payload):
            return None
        sid_len = payload[pos]
        pos += 1 + sid_len

        if pos + 2 > len(payload):
            return None
        cs_len = _U16.unpack_from(payload, pos)[0]
        pos += 2 + cs_len

        if pos + 1 > len(payload):
            return None
        cm_len = payload[pos]
        pos += 1 + cm_len

        if pos + 2 > len(payload):
            return None
        ext_total_len = _U16.unpack_from(payload, pos)[0]
        pos += 2

        ext_end = pos + ext_total_len
        has_ech = False
        sni = None

        # ГЛАВНЫЙ ФИКС: ограничиваем цикл реальной длиной пакета (len(payload))
        while pos + TLS_EXT_HEADER_LEN <= len(payload) and pos < ext_end:
            ext_type = _U16.unpack_from(payload, pos)[0]
            ext_len = _U16.unpack_from(payload, pos + 2)[0]
            if ext_type == TLS_ECH_EXT_TYPE:
                has_ech = True

            ext_limit = pos + TLS_EXT_HEADER_LEN + ext_len
            pos += TLS_EXT_HEADER_LEN

            if ext_type == TLS_SNI_EXT_TYPE and sni is None:
                if pos + 5 > len(payload):
                    return None
                name_type = payload[pos + 2]
                name_len = _U16.unpack_from(payload, pos + 3)[0]
                host_off = pos + 5

                # Проверяем, что имя не вылезает за реальный буфер
                if name_type == 0 and name_len > 0:
                    if host_off + name_len > len(payload):
                        return None
                    sni = (host_off, payload[host_off:host_off + name_len])

            pos = ext_limit

        if has_ech:
            return ("ech", sni)
        return sni

    @staticmethod
    def _midsld_offset(hostname):
        """Вычисляет середину домена второго уровня (SLD)."""
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
        """Определяет индекс байта для разрыва пакета."""
        h = hostname.rstrip(b".")
        mode = self.cfg.split_pos
        if mode == "midsld":
            rel = self._midsld_offset(h)
            if rel is not None:
                return host_off + rel
        # Фолбэк — случайная точка внутри имени
        n = len(h)
        if n >= 2:
            return host_off + random.randint(1, n - 1)
        return host_off + max(0, n)

    def _fragment_and_send(self, packet, payload, host_off, hostname):
        """Разрезает пакет и отправляет (с опциональным добавлением фейков или 3-way сплитом)."""
        split_at = self._split_offset_for_match(host_off, hostname)

        split_at = max(split_at, 1)
        if split_at >= len(payload) - 1:
            # Сплит невозможен — отправляем как есть.
            self._send_with_checksum(packet)
            return

        self._mark_bypassed(len(payload))

        first = payload[:split_at]
        second = payload[split_at:]
        seq = packet.tcp.seq_num

        disorder = self.mode.endswith("disorder")
        use_fake = self.mode.startswith("fake")
        use_triple = "triple" in self.mode

        try:
            # 1. Режимы с фейком (fake+split / fake+disorder)
            if use_fake:
                fake_payload = self._make_fake(payload, host_off, hostname,
                                            self.cfg.fake_sni_tld)
                if fake_payload is None:
                    # Не удалось собрать фейк (слишком короткий SNI)
                    self._send_pair(packet, first, second, seq, split_at, disorder)
                    return

                self._send_fakes(packet, fake_payload)
                self._schedule(
                    self.cfg.fake_split_delay_s,
                    lambda: self._send_pair(
                        packet, first, second, seq, split_at, disorder),
                )
                return

            # 2. Режимы с тройным сплитом (triple_split / triple_disorder)
            if use_triple:
                self._send_triple(packet, payload, host_off, hostname, seq, disorder)
                return

            # 3. Обычный сплит (split / disorder)
            self._send_pair(packet, first, second, seq, split_at, disorder)

        except Exception as e:
            self.log(f"frag error: {e}")
            try:
                self._send_with_checksum(packet)
            except Exception:
                pass

    def _send_fakes(self, packet, fake_payload):
        """Отправляет N фейковых пакетов с низким TTL."""
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
    def _fake_sni(n, tld, exclude=None):
        """Генерирует случайный SNI, гарантируя отсутствие коллизий."""
        suffix = b"." + tld
        label_len = n - len(suffix)
        if label_len < 1:
            return None
        label = bytes(
            random.choices(b"abcdefghijklmnopqrstuvwxyz", k=label_len)
        )
        result = label + suffix
        # Защита от совпадения с реальным доменом (x.com -> x.com)
        if exclude is not None and result.lower() == exclude.lower():
            first = label[0:1]
            new_first = b"a" if first != b"a" else b"b"
            result = new_first + label[1:] + suffix

        return result

    @staticmethod
    def _make_fake(payload, host_off, hostname, tld):
        """Подменяет реальный SNI на фейковый в копии пакета."""
        n = len(hostname)
        if n == 0:
            return None

        rep = DpiBypass._fake_sni(n, tld, exclude=hostname)
        if rep is None or len(rep) != n:
            return None

        fake = bytearray(payload)
        fake[host_off:host_off + n] = rep
        return bytes(fake)

    def _send_triple(self, packet, payload, host_off, hostname, seq, disorder=False):
        """Разрезает пакет на 3 части (triple_split / triple_disorder)."""
        h = hostname.rstrip(b".")
        n = len(h)
        
        # Вычисляем две точки разрыва внутри домена
        if n >= 3:
            mid1 = host_off + max(1, n // 3)
            mid2 = host_off + max(2, (2 * n) // 3)
        else:
            mid1 = len(payload) // 3
            mid2 = (len(payload) * 2) // 3

        # Защита, чтобы куски не были пустыми и не вылезали за границы
        if mid1 < 1 or mid2 <= mid1 or mid2 >= len(payload) - 1:
            # Если домен слишком короткий — откатываемся на обычный split
            fallback_split = len(payload) // 2
            first = payload[:fallback_split]
            second = payload[fallback_split:]
            self._send_pair(packet, first, second, seq, fallback_split, disorder)
            return

        first = payload[:mid1]
        second = payload[mid1:mid2]
        third = payload[mid2:]

        if disorder:
            # triple_disorder: отправляем 3-ю, 1-ю, затем 2-ю (с задержкой)
            p3 = self._clone_packet(packet)
            p3.payload = third
            p3.tcp.seq_num = (seq + mid2) & SEQ_MASK
            p3.tcp.psh = True
            self._send_with_checksum(p3)
            
            p1 = self._clone_packet(packet)
            p1.payload = first
            p1.tcp.seq_num = seq
            p1.tcp.psh = False
            self._send_with_checksum(p1)

            def resend_mid():
                p2 = self._clone_packet(packet)
                p2.payload = second
                p2.tcp.seq_num = (seq + mid1) & SEQ_MASK
                p2.tcp.psh = False
                self._send_with_checksum(p2)
                
            self._schedule(self.cfg.disorder_delay_s, resend_mid)
        else:
            # triple_split: отправляем 1-ю, 2-ю, 3-ю по порядку
            packet.payload = first
            packet.tcp.seq_num = seq
            packet.tcp.psh = False
            self._send_with_checksum(packet)

            packet.payload = second
            packet.tcp.seq_num = (seq + mid1) & SEQ_MASK
            packet.tcp.psh = False
            self._send_with_checksum(packet)

            packet.payload = third
            packet.tcp.seq_num = (seq + mid2) & SEQ_MASK
            packet.tcp.psh = True
            self._send_with_checksum(packet)

    def _send_pair(self, packet, first, second, seq, split_at, disorder=False):
        """Отправляет две половины пакета (в нужном или обратном порядке)."""
        if disorder:
            # Сначала вторая половина, затем (с задержкой) первая
            p2 = self._clone_packet(packet)
            p2.payload = second
            p2.tcp.seq_num = (seq + split_at) & SEQ_MASK
            p2.tcp.psh = False
            self._send_with_checksum(p2)

            def resend_first():
                packet.payload = first
                packet.tcp.seq_num = seq
                packet.tcp.psh = True
                self._send_with_checksum(packet)

            self._schedule(self.cfg.disorder_delay_s, resend_first)
        else:
            # Отправляем первую половину (мутируем оригинал)
            packet.payload = first
            packet.tcp.seq_num = seq
            packet.tcp.psh = False
            self._send_with_checksum(packet)

            # Отправляем вторую половину (тот же оригинал)
            packet.payload = second
            packet.tcp.seq_num = (seq + split_at) & SEQ_MASK
            packet.tcp.psh = True
            self._send_with_checksum(packet)
