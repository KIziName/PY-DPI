"""Тесты внутренней логики: склейка пакетов и маршрутизация режимов."""
import time
import unittest
from unittest.mock import MagicMock

from bypass import DpiBypass, PendingState
from test_tls import mk_client_hello
from config import SEQ_MASK


class _FakeTCP:
    def __init__(self, seq_num):
        self.seq_num = seq_num
        self.psh = True


class _FakePacket:
    def __init__(self, seq_num):
        self.tcp = _FakeTCP(seq_num)
        self.ipv4 = MagicMock()
        self.ipv6 = None


class TestContinuePending(unittest.TestCase):

    def setUp(self):
        self.bp = DpiBypass(["example.com"], "split", lambda m: None)
        self.key = ("1.1.1.1", 1234, "2.2.2.2", 443)
        
        # Мокаем отправку, чтобы она ничего не делала
        self.bp._send_one = MagicMock()
        self.bp._fragment_and_send = MagicMock()
        self.bp._dispatch_fresh = MagicMock()
        self.bp._flush_as_is = MagicMock()

    def test_sequential_reassembly_success(self):
        # Разрезаем ClientHello на две части
        ch = mk_client_hello()
        part1 = ch[:40]
        part2 = ch[40:]
        
        pkt1 = _FakePacket(seq_num=1000)
        pkt2 = _FakePacket(seq_num=1000 + len(part1))

        # Кладем первый кусок в буфер
        self.bp._pending[self.key] = PendingState(
            buf=part1, ts=time.monotonic(), packets=[pkt1], first_seq=1000)

        # Приходит второй кусок
        self.bp._continue_pending(self.key, pkt2, part2)

        # Буфер должен очиститься, пакеты отправлены БЕЗ обхода
        self.assertNotIn(self.key, self.bp._pending)
        self.bp._flush_as_is.assert_called_once()        # отправка 1-го куска
        self.bp._send_one.assert_called_once_with(pkt2)  # отправка 2-го куска

    def test_retransmission_ignored(self):
        ch = mk_client_hello()
        part1 = ch[:40]
        
        pkt1 = _FakePacket(seq_num=1000)
        # Дубликат пакета 1
        pkt_dup = _FakePacket(seq_num=1000)

        self.bp._pending[self.key] = PendingState(
            buf=part1, ts=time.monotonic(), packets=[pkt1], first_seq=1000)

        self.bp._continue_pending(self.key, pkt_dup, part1)

        # Пакет проигнорирован: отправки не было, буфер на месте
        self.bp._send_one.assert_not_called()
        self.assertIn(self.key, self.bp._pending)

    def test_sequence_gap_flushes_pending(self):
        ch = mk_client_hello()
        part1 = ch[:40]
        
        pkt1 = _FakePacket(seq_num=1000)
        # Пакет с неверным seq (разрыв)
        pkt_gap = _FakePacket(seq_num=9999)

        self.bp._pending[self.key] = PendingState(
            buf=part1, ts=time.monotonic(), packets=[pkt1], first_seq=1000)

        self.bp._continue_pending(self.key, pkt_gap, b"new data")

        # Буфер должен быть сброшен, а новый пакет обработан с нуля
        self.assertNotIn(self.key, self.bp._pending)
        self.bp._flush_as_is.assert_called_once()
        self.bp._dispatch_fresh.assert_called_once()


class TestFragmentRouting(unittest.TestCase):
    
    def setUp(self):
        self.payload = b"A" * 100
        self.host_off = 10
        self.hostname = b"example.com"
        self.packet = MagicMock()

    def _run_mode(self, mode):
        bp = DpiBypass([], mode, lambda m: None)
        bp._send_pair = MagicMock()
        bp._send_triple = MagicMock()
        bp._send_fakes = MagicMock()
        bp._schedule = MagicMock()
        
        # Отключаем проверку длины, чтобы гарантированно пройти дальше
        bp._split_offset_for_match = MagicMock(return_value=50)
        
        bp._fragment_and_send(self.packet, self.payload, self.host_off, self.hostname)
        return bp

    def test_split_routes_to_send_pair(self):
        bp = self._run_mode("split")
        bp._send_pair.assert_called_once()
        bp._send_triple.assert_not_called()

    def test_triple_split_routes_to_send_triple(self):
        bp = self._run_mode("triple_split")
        bp._send_triple.assert_called_once()
        bp._send_pair.assert_not_called()

    def test_triple_disorder_routes_to_send_triple(self):
        bp = self._run_mode("triple_disorder")
        bp._send_triple.assert_called_once()
        # В disorder передается True
        args, kwargs = bp._send_triple.call_args
        self.assertTrue(args[-1]) # disorder=True

    def test_fake_split_routes_to_fakes_and_pair(self):
        bp = self._run_mode("fake+split")
        # 1. Проверяем, что фейк был отправлен
        bp._send_fakes.assert_called_once()
        # 2. Проверяем, что реальный пакет был поставлен в очередь
        bp._schedule.assert_called_once()
        # 3. Выполняем лямбду из _schedule вручную, чтобы проверить,
        # что она внутри себя вызывает _send_pair (как и задумано)
        # В MagicMock аргументы хранятся в call_args: первый - delay, второй - функция
        scheduled_func = bp._schedule.call_args[0][1]
        scheduled_func()
        # 4. Теперь проверяем, что реальный пакет ушел через _send_pair
        bp._send_pair.assert_called_once()
        bp._send_triple.assert_not_called()
