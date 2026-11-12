"""Тесты TLS-парсера."""
import unittest

from bypass import DpiBypass


def mk_client_hello(sni=b"example.com"):
    name = b"\x00" + len(sni).to_bytes(2, "big") + sni
    sni_list = len(name).to_bytes(2, "big") + name
    ext = b"\x00\x00" + len(sni_list).to_bytes(2, "big") + sni_list
    exts = len(ext).to_bytes(2, "big") + ext
    body = (b"\x03\x03" + b"\x00" * 32 + b"\x00"
            + b"\x00\x02\x00\x2f" + b"\x01\x00" + exts)
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + len(hs).to_bytes(2, "big") + hs


class TestTlsSni(unittest.TestCase):

    def test_simple(self):
        ch = mk_client_hello(b"example.com")
        off, host = DpiBypass._tls_sni(ch)
        self.assertEqual(host, b"example.com")
        self.assertEqual(ch[off:off + 11], b"example.com")

    def test_long(self):
        name = b"very-long-subdomain.example.org"
        off, host = DpiBypass._tls_sni(mk_client_hello(name))
        self.assertEqual(host, name)

    def test_garbage(self):
        self.assertIsNone(DpiBypass._tls_sni(b"\xff" * 100))

    def test_empty(self):
        self.assertIsNone(DpiBypass._tls_sni(b""))

    def test_not_handshake(self):
        self.assertIsNone(DpiBypass._tls_sni(b"\x17\x03\x01\x00\x00"))

    def test_wrong_type(self):
        ch = bytearray(mk_client_hello())
        ch[5] = 0x02
        self.assertIsNone(DpiBypass._tls_sni(bytes(ch)))


class TestTlsStart(unittest.TestCase):

    def test_valid(self):
        self.assertTrue(DpiBypass._is_tls_clienthello_start(
            mk_client_hello()))

    def test_not_clienthello(self):
        self.assertFalse(DpiBypass._is_tls_clienthello_start(
            b"\x16\x03\x01\x00\x10\x02"))

    def test_too_short(self):
        self.assertFalse(DpiBypass._is_tls_clienthello_start(b"\x16"))
        
class TestTlsRecordIncomplete(unittest.TestCase):

    def test_complete_record(self):
        ch = mk_client_hello()
        self.assertFalse(DpiBypass._tls_record_incomplete(ch))

    def test_truncated_record(self):
        ch = mk_client_hello()
        self.assertTrue(DpiBypass._tls_record_incomplete(ch[:10]))

    def test_not_tls(self):
        self.assertFalse(DpiBypass._tls_record_incomplete(b"\x17\x03\x01\x00\x00"))

    def test_short_header(self):
        self.assertTrue(DpiBypass._tls_record_incomplete(b"\x16\x03"))

    def mk_client_hello_ech():
    """ClientHello с расширением ECH (0xfe0d), но БЕЗ обычного SNI."""
    # ECH ext: type 0xfe0d, len 4, data 0000
    ech_ext = b"\xfe\x0d\x00\x04\x00\x00\x00\x00"
    exts = len(ech_ext).to_bytes(2, "big") + ech_ext
    body = (b"\x03\x03" + b"\x00" * 32 + b"\x00"
            + b"\x00\x02\x00\x2f" + b"\x01\x00" + exts)
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + len(hs).to_bytes(2, "big") + hs


class TestECH(unittest.TestCase):

    def test_tls_sni_returns_ech(self):
        ch = mk_client_hello_ech()
        result = DpiBypass._tls_sni(ch)
        self.assertEqual(result, ("ech", None))

    def test_tls_sni_returns_normal_if_sni_exists(self):
        # Если есть и SNI и ECH, приоритет отдается SNI (программа обойдет его)
        ch = mk_client_hello(b"example.com")
        off, host = DpiBypass._tls_sni(ch)
        self.assertEqual(host, b"example.com")

if __name__ == "__main__":
    unittest.main()
