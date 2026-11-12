"""Тесты безопасности и фильтрации трафика (process)."""
import unittest
from dataclasses import replace
from unittest.mock import MagicMock

from bypass import DpiBypass


class _FakeUDP:
    def __init__(self, dst_port=443):
        self.dst_port = dst_port


class _FakeTCP:
    def __init__(self, src_port=1234, dst_port=443):
        self.src_port = src_port
        self.dst_port = dst_port


class _FakeIPv4:
    def __init__(self, dst_addr="142.250.0.1", src_addr="192.168.1.1"):
        self.dst_addr = dst_addr
        self.src_addr = src_addr


class _FakePacket:
    def __init__(self, tcp=None, udp=None, ipv4=None, ipv6=None, payload=b""):
        self.tcp = tcp
        self.udp = udp
        self.ipv4 = ipv4
        self.ipv6 = ipv6
        self.payload = payload


# ─── QUIC (UDP/443) ────────────────────────────────────────────

class TestProcessQUIC(unittest.TestCase):
    """Тесты блока QUIC (UDP/443)."""

    def setUp(self):
        self.bp = DpiBypass([], "split", lambda m: None)
        self.bp._send_one = MagicMock()

    def test_quic_public_ip_dropped(self):
        """UDP/443 на публичный IP — дроп (чтобы браузер перешел на TCP)."""
        pkt = _FakePacket(
            udp=_FakeUDP(dst_port=443),
            ipv4=_FakeIPv4(dst_addr="142.250.0.1"),
            ipv6=None,
        )
        self.bp.process(pkt)
        self.bp._send_one.assert_not_called()
        self.assertEqual(self.bp.packets_quic_dropped, 1)

    def test_quic_local_ip_passes(self):
        """UDP/443 на локальный IP — пропускается (не трогаем свою сеть)."""
        pkt = _FakePacket(
            udp=_FakeUDP(dst_port=443),
            ipv4=_FakeIPv4(dst_addr="192.168.1.1"),
            ipv6=None,
        )
        self.bp.process(pkt)
        self.bp._send_one.assert_called_once_with(pkt)
        self.assertEqual(self.bp.packets_quic_dropped, 0)

    def test_udp_other_port_passes(self):
        """UDP на другой порт (например, 53 DNS) — пропускается."""
        pkt = _FakePacket(
            udp=_FakeUDP(dst_port=53),
            ipv4=_FakeIPv4(dst_addr="142.250.0.1"),
            ipv6=None,
        )
        self.bp.process(pkt)
        self.bp._send_one.assert_called_once_with(pkt)

    def test_quic_disabled_passes(self):
        """Если block_quic=False — UDP/443 проходит насквозь."""
        cfg = replace(self.bp.cfg, block_quic=False)
        bp = DpiBypass([], "split", lambda m: None, config=cfg)
        bp._send_one = MagicMock()
        pkt = _FakePacket(
            udp=_FakeUDP(dst_port=443),
            ipv4=_FakeIPv4(dst_addr="142.250.0.1"),
            ipv6=None,
        )
        bp.process(pkt)
        bp._send_one.assert_called_once_with(pkt)
        self.assertEqual(bp.packets_quic_dropped, 0)

    def test_no_tcp_no_udp_passes(self):
        """Битый пакет (нет ни TCP, ни UDP) — просто отправляем."""
        pkt = _FakePacket(tcp=None, udp=None, ipv4=_FakeIPv4())
        self.bp.process(pkt)
        self.bp._send_one.assert_called_once_with(pkt)


# ─── TCP (фильтрация) ─────────────────────────────────────────

class TestProcessTCP(unittest.TestCase):
    """Тесты фильтрации TCP-пакетов."""

    def setUp(self):
        self.bp = DpiBypass([], "split", lambda m: None)
        self.bp._send_one = MagicMock()
        self.bp._dispatch_fresh = MagicMock()
        self.bp._continue_pending = MagicMock()

    def test_empty_payload_passes(self):
        """TCP без payload (чистый ACK) — отправляем."""
        pkt = _FakePacket(
            tcp=_FakeTCP(),
            ipv4=_FakeIPv4(dst_addr="142.250.0.1"),
            payload=b"",
        )
        self.bp.process(pkt)
        self.bp._send_one.assert_called_once_with(pkt)
        self.bp._dispatch_fresh.assert_not_called()

    def test_non_our_first_byte_passes(self):
        """Не TLS (0x16) и не HTTP — отправляем без обхода."""
        pkt = _FakePacket(
            tcp=_FakeTCP(),
            ipv4=_FakeIPv4(dst_addr="142.250.0.1"),
            payload=b"\x00garbage",
        )
        self.bp.process(pkt)
        self.bp._send_one.assert_called_once_with(pkt)
        self.bp._dispatch_fresh.assert_not_called()

    def test_local_ip_passes(self):
        """TCP на локальный IP — отправляем без обхода, даже если payload наш."""
        pkt = _FakePacket(
            tcp=_FakeTCP(),
            ipv4=_FakeIPv4(dst_addr="192.168.1.1"),
            payload=b"\x16\x03\x01\x00\x50...",
        )
        self.bp.process(pkt)
        self.bp._send_one.assert_called_once_with(pkt)
        self.bp._dispatch_fresh.assert_not_called()

    def test_public_ip_dispatches(self):
        """TLS ClientHello (0x16) на публичный IP — идём в dispatch."""
        pkt = _FakePacket(
            tcp=_FakeTCP(),
            ipv4=_FakeIPv4(dst_addr="142.250.0.1"),
            payload=b"\x16\x03\x01\x00\x50...",
        )
        self.bp.process(pkt)
        self.bp._dispatch_fresh.assert_called_once()

    def test_http_request_dispatches(self):
        """HTTP GET на публичный IP — тоже идёт в dispatch."""
        pkt = _FakePacket(
            tcp=_FakeTCP(),
            ipv4=_FakeIPv4(dst_addr="142.250.0.1"),
            payload=b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
        )
        self.bp.process(pkt)
        self.bp._dispatch_fresh.assert_called_once()

    def test_pending_goes_to_continue(self):
        """Если есть pending — идём в continue_pending, а не в fresh."""
        pkt = _FakePacket(
            tcp=_FakeTCP(),
            ipv4=_FakeIPv4(dst_addr="142.250.0.1"),
            payload=b"\x16\x03\x01\x00\x50...",
        )
        key = self.bp._conn_key(pkt)
        self.bp._pending[key] = MagicMock()  # маркер наличия pending
        try:
            self.bp.process(pkt)
            self.bp._continue_pending.assert_called_once_with(
                key, pkt, pkt.payload)
            self.bp._dispatch_fresh.assert_not_called()
        finally:
            self.bp._pending.clear()

    def test_stop_event_sends_anyway(self):
        """Если _stop_event установлен — отправляем без всяких проверок."""
        self.bp._stop_event.set()
        pkt = _FakePacket(
            tcp=_FakeTCP(),
            ipv4=_FakeIPv4(dst_addr="142.250.0.1"),
            payload=b"\x16\x03\x01\x00\x50...",
        )
        try:
            self.bp.process(pkt)
            self.bp._send_one.assert_called_once_with(pkt)
            self.bp._dispatch_fresh.assert_not_called()
        finally:
            self.bp._stop_event.clear()


if __name__ == "__main__":
    unittest.main()