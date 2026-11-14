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
        self.key = ("1.1.1.1", 1234, "2.2.2.2", 443)
        self.ch = mk_client_hello() # example.com
        self.part1 = self.ch[:40]
        self.part2 = self.ch[40:]
        
        self.pkt1 = _FakePacket(seq_num=1000)
        self.pkt2 = _FakePacket(seq_num=1000 + len(self.part1))

    def test_sequential_reassembly_no_bypass(self):
        # Домен, которого НЕТ в списке обхода (other.com) - должен уйти как есть
        bp = DpiBypass(["other.com"], "split", lambda m: None)
        bp._send_one = MagicMock()
        bp._flush_as_is = MagicMock()
        bp._dispatch_fresh = MagicMock()

        bp._pending[self.key] = PendingState(
            buf=self.part1, ts=time.monotonic(), packets=[self.pkt1], first_seq=1000)

        bp._continue_pending(self.key, self.pkt2, self.part2)

        # Буфер очищен, пакеты отправлены БЕЗ обхода
        self.assertNotIn(self.key, bp._pending)
        bp._flush_as_is.assert_called_once()        
        bp._send_one.assert_called_once_with(self.pkt2)  

    def test_sequential_reassembly_with_bypass(self):
        # Домен, который ЕСТЬ в списке обхода (example.com) - должен нарезаться заново
        bp = DpiBypass(["example.com"], "split", lambda m: None)
        bp._send_one = MagicMock()
        bp._fragment_and_send = MagicMock()
        bp._flush_as_is = MagicMock()

        bp._pending[self.key] = PendingState(
            buf=self.part1, ts=time.monotonic(), packets=[self.pkt1], first_seq=1000)

        bp._continue_pending(self.key, self.pkt2, self.part2)

        # Буфер очищен, пакет должен уйти в _fragment_and_send
        self.assertNotIn(self.key, bp._pending)
        bp._fragment_and_send.assert_called_once()
        bp._flush_as_is.assert_not_called()
        bp._send_one.assert_not_called()

    def test_retransmission_ignored(self):
        bp = DpiBypass(["example.com"], "split", lambda m: None)
        bp._send_one = MagicMock()
        
        pkt_dup = _FakePacket(seq_num=1000)

        bp._pending[self.key] = PendingState(
            buf=self.part1, ts=time.monotonic(), packets=[self.pkt1], first_seq=1000)

        bp._continue_pending(self.key, pkt_dup, self.part1)

        # Пакет проигнорирован: отправки не было, буфер на месте
        bp._send_one.assert_not_called()
        self.assertIn(self.key, bp._pending)

    def test_sequence_gap_flushes_pending(self):
        bp = DpiBypass(["example.com"], "split", lambda m: None)
        bp._flush_as_is = MagicMock()
        bp._dispatch_fresh = MagicMock()

        pkt_gap = _FakePacket(seq_num=9999)

        bp._pending[self.key] = PendingState(
            buf=self.part1, ts=time.monotonic(), packets=[self.pkt1], first_seq=1000)

        bp._continue_pending(self.key, pkt_gap, b"new data")

        # Буфер должен быть сброшен, а новый пакет обработан с нуля
        self.assertNotIn(self.key, bp._pending)
        bp._flush_as_is.assert_called_once()
        bp._dispatch_fresh.assert_called_once()


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
        args, kwargs = bp._send_triple.call_args
        self.assertTrue(args[-1]) # disorder=True

    def test_fake_split_routes_to_fakes_and_pair(self):
        bp = self._run_mode("fake+split")
        bp._send_fakes.assert_called_once()
        bp._schedule.assert_called_once()
        
        scheduled_func = bp._schedule.call_args[0][1]
        scheduled_func()
        
        bp._send_pair.assert_called_once()
        bp._send_triple.assert_not_called()
