"""Тесты мутации пакетов: seq-номера, PSH-флаги, чексуммы, TTL."""
import unittest
from dataclasses import replace
from unittest.mock import MagicMock

from bypass import DpiBypass
from config import SEQ_MASK


class _MutableTCP:
    def __init__(self, seq_num=1000):
        self.seq_num = seq_num
        self.psh = True
        self.checksum = 0x1234


class _MutablePacket:
    def __init__(self, payload=b"", seq_num=1000, ipv4=None):
        self.payload = payload
        self.tcp = _MutableTCP(seq_num)
        self.ipv4 = ipv4
        self.ipv6 = None
        self.interface = None
        self.direction = None

    def recalculate_checksums(self):
        # Заглушка — реальная логика pydivert тут не нужна
        pass


def _make_pkt(seq_num=1000, ipv4=None):
    return _MutablePacket(seq_num=seq_num, ipv4=ipv4)


# ─────────────── _send_pair ───────────────

class TestSendPair(unittest.TestCase):
    """Проверяем математику split/disorder в _send_pair."""

    def setUp(self):
        self.bp = DpiBypass([], "split", lambda m: None)
        self.calls = []
        self.bp._send_one = MagicMock(
            side_effect=lambda p: self.calls.append(
                (bytes(p.payload), p.tcp.seq_num, p.tcp.psh)))

    def test_split_two_parts_in_order(self):
        """split: сначала первая половина (psh=False), потом вторая (psh=True)."""
        pkt = _make_pkt(seq_num=1000)
        self.bp._send_pair(pkt, b"HELLO", b"WORLD", 1000, 5, disorder=False)
        self.assertEqual(self.calls, [
            (b"HELLO", 1000, False),
            (b"WORLD", 1005, True),
        ])

    def test_split_seq_wraps_at_mask(self):
        """seq_num + split_at должен обернуться через SEQ_MASK."""
        pkt = _make_pkt(seq_num=0xFFFFFFFD)
        self.bp._send_pair(pkt, b"AAA", b"BBB", 0xFFFFFFFD, 3, disorder=False)
        self.assertEqual(self.calls[1][1], 0)

    def test_disorder_sends_second_first(self):
        """disorder: сначала вторая половина, потом (по расписанию) первая."""
        self.bp._schedule = MagicMock()
        pkt = _make_pkt(seq_num=1000)
        self.bp._send_pair(pkt, b"HELLO", b"WORLD", 1000, 5, disorder=True)

        # Вторая половина ушла сразу
        self.assertEqual(self.calls[0], (b"WORLD", 1005, False))
        # Расписание создано
        self.bp._schedule.assert_called_once()

        # Выполняем запланированное
        self.bp._schedule.call_args[0][1]()
        self.assertEqual(self.calls[1], (b"HELLO", 1000, True))


# ─────────────── _send_triple ───────────────

class TestSendTriple(unittest.TestCase):
    """Проверяем математику split/disorder в _send_triple."""

    def setUp(self):
        self.bp = DpiBypass([], "triple_split", lambda m: None)
        self.calls = []
        self.bp._send_one = MagicMock(
            side_effect=lambda p: self.calls.append(
                (bytes(p.payload), p.tcp.seq_num, p.tcp.psh)))

    def test_triple_split_three_parts(self):
        """triple_split: три части по порядку, psh=True только у последней."""
        # hostname="a.com" → n=5, mid1=1, mid2=3
        # payload = 10 байт → first=b"A", second=b"BC", third=b"DEFGHIJ"
        pkt = _make_pkt(seq_num=1000)
        self.bp._send_triple(
            pkt, b"ABCDEFGHIJ", 0, b"a.com", 1000, disorder=False)

        self.assertEqual(self.calls, [
            (b"A", 1000, False),
            (b"BC", 1001, False),
            (b"DEFGHIJ", 1003, True),
        ])

    def test_triple_falls_back_on_short_payload(self):
        """Если payload слишком короткий — вызываем _send_pair."""
        self.bp._send_pair = MagicMock()
        pkt = _make_pkt()
        self.bp._send_triple(
            pkt, b"ABC", 0, b"a.com", 1000, disorder=False)
        self.bp._send_pair.assert_called_once()

    def test_triple_disorder_order(self):
        """triple_disorder: 3-я, 1-я, потом 2-я (по расписанию)."""
        self.bp._schedule = MagicMock()
        pkt = _make_pkt(seq_num=1000)
        self.bp._send_triple(
            pkt, b"ABCDEFGHIJ", 0, b"a.com", 1000, disorder=True)

        # Сначала 3-я часть (seq+mid2, psh=True)
        self.assertEqual(self.calls[0], (b"DEFGHIJ", 1003, True))
        # Потом 1-я часть (seq, psh=False)
        self.assertEqual(self.calls[1], (b"A", 1000, False))

        # Запланированная 2-я часть
        self.bp._schedule.call_args[0][1]()
        self.assertEqual(self.calls[2], (b"BC", 1001, False))


# ─────────────── _send_badsum ───────────────

class TestSendBadsum(unittest.TestCase):
    """Проверяем, что чексумма реально ломается."""

    def setUp(self):
        self.bp = DpiBypass([], "split", lambda m: None)
        self.bp._send_one = MagicMock()

    def test_checksum_is_corrupted(self):
        """После 100 вызовов чексумма ни разу не совпала с исходной и не стала 0."""
        for _ in range(100):
            pkt = _make_pkt()
            pkt.tcp.checksum = 0x1234
            self.bp._send_badsum(pkt)
            self.assertNotEqual(pkt.tcp.checksum, 0x1234,
                                "чексумма не изменилась")
            self.assertNotEqual(pkt.tcp.checksum, 0,
                                "чексумма стала нулевой")

    def test_badsum_sends_packet(self):
        pkt = _make_pkt()
        self.bp._send_badsum(pkt)
        self.bp._send_one.assert_called_once_with(pkt)


# ─────────────── _send_fakes ───────────────

class TestSendFakes(unittest.TestCase):
    """Проверяем TTL и количество повторов в _send_fakes."""

    def _make_bp(self, ttl=5, repeats=3, badsum=False):
        cfg = replace(DpiBypass([], "split", lambda m: None).cfg,
                      fake_ttl=ttl, fake_repeats=repeats, fake_badsum=badsum)
        return DpiBypass([], "fake+split", lambda m: None, config=cfg)

    def test_repeats_and_ttl(self):
        """3 повтора → 3 пакета, у каждого ttl=5."""
        bp = self._make_bp(ttl=5, repeats=3, badsum=False)
        bp._send_with_checksum = MagicMock()
        bp._clone_packet = MagicMock(side_effect=lambda p: _make_pkt(ipv4=MagicMock()))

        pkt = _make_pkt(ipv4=MagicMock())
        bp._send_fakes(pkt, b"fake.example.com")

        self.assertEqual(bp._send_with_checksum.call_count, 3)
        for call in bp._send_with_checksum.call_args_list:
            fake = call[0][0]
            self.assertEqual(fake.ipv4.ttl, 5)

    def test_badsum_path(self):
        """Если fake_badsum=True → вызывается _send_badsum, а не _send_with_checksum."""
        bp = self._make_bp(ttl=3, repeats=2, badsum=True)
        bp._send_badsum = MagicMock()
        bp._send_with_checksum = MagicMock()
        bp._clone_packet = MagicMock(side_effect=lambda p: _make_pkt(ipv4=MagicMock()))

        pkt = _make_pkt(ipv4=MagicMock())
        bp._send_fakes(pkt, b"fake.example.com")

        self.assertEqual(bp._send_badsum.call_count, 2)
        bp._send_with_checksum.assert_not_called()


if __name__ == "__main__":
    unittest.main()