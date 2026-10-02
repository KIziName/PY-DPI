"""Тесты ключа TCP-соединения."""
import unittest

from bypass import DpiBypass


class _FakeTCP:
    def __init__(self, src_port, dst_port):
        self.src_port = src_port
        self.dst_port = dst_port


class _FakeIP:
    def __init__(self, src, dst):
        self.src_addr = src
        self.dst_addr = dst


class _FakePacket:
    def __init__(self, tcp=None, ipv4=None, ipv6=None):
        self.tcp = tcp
        self.ipv4 = ipv4
        self.ipv6 = ipv6


class TestConnKey(unittest.TestCase):

    def test_none_without_tcp(self):
        p = _FakePacket(ipv4=_FakeIP("1.2.3.4", "5.6.7.8"))
        self.assertIsNone(DpiBypass._conn_key(p))

    def test_none_without_ip(self):
        p = _FakePacket(tcp=_FakeTCP(1234, 443))
        self.assertIsNone(DpiBypass._conn_key(p))

    def test_ipv4_key(self):
        p = _FakePacket(
            tcp=_FakeTCP(1234, 443),
            ipv4=_FakeIP("1.2.3.4", "5.6.7.8"),
        )
        self.assertEqual(
            DpiBypass._conn_key(p),
            ("1.2.3.4", 1234, "5.6.7.8", 443),
        )

    def test_ipv6_key(self):
        p = _FakePacket(
            tcp=_FakeTCP(1234, 443),
            ipv6=_FakeIP("2001:db8::1", "2001:db8::2"),
        )
        self.assertEqual(
            DpiBypass._conn_key(p),
            ("2001:db8::1", 1234, "2001:db8::2", 443),
        )

    def test_ipv4_preferred_over_ipv6(self):
        p = _FakePacket(
            tcp=_FakeTCP(1, 2),
            ipv4=_FakeIP("1.1.1.1", "2.2.2.2"),
            ipv6=_FakeIP("::1", "::2"),
        )
        self.assertEqual(
            DpiBypass._conn_key(p),
            ("1.1.1.1", 1, "2.2.2.2", 2),
        )

    def test_broken_attrs_return_none(self):
        class BadIP:
            @property
            def src_addr(self):
                raise RuntimeError("boom")

            @property
            def dst_addr(self):
                raise RuntimeError("boom")

        p = _FakePacket(tcp=_FakeTCP(1, 2), ipv4=BadIP())
        self.assertIsNone(DpiBypass._conn_key(p))