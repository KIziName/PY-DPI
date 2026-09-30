"""Тесты хелперов: midsld, fake_sni, make_fake."""
import unittest
from config import FAKE_SNI_BASE
from dpi import DpiBypass


class TestMidsld(unittest.TestCase):

    def test_simple(self):
        self.assertEqual(DpiBypass._midsld_offset(b"example.com"), 3)

    def test_www(self):
        self.assertEqual(DpiBypass._midsld_offset(b"www.example.com"), 7)

    def test_too_short(self):
        self.assertIsNone(DpiBypass._midsld_offset(b"ab"))

    def test_single_char_sld(self):
        self.assertIsNone(DpiBypass._midsld_offset(b"a.com"))

    def test_no_dots(self):
        self.assertEqual(DpiBypass._midsld_offset(b"abcdef"), 3)


class TestFakeSni(unittest.TestCase):

    def test_length(self):
        for n in (10, 20, 30):
            rep = DpiBypass._fake_sni(n)
            self.assertIsNotNone(rep)
            self.assertEqual(len(rep), n)

    def test_same_as_base(self):
        self.assertEqual(DpiBypass._fake_sni(len(FAKE_SNI_BASE)),
                         FAKE_SNI_BASE)

    def test_too_short(self):
        self.assertIsNone(DpiBypass._fake_sni(0))
        self.assertIsNone(DpiBypass._fake_sni(3))


class TestMakeFake(unittest.TestCase):

    def test_preserves_length(self):
        host = b"example.com"
        payload = b"AAA" + host + b"BBB"
        fake = DpiBypass._make_fake(payload, 3, host)
        self.assertIsNotNone(fake)
        self.assertEqual(len(fake), len(payload))

    def test_prefix_suffix_untouched(self):
        host = b"example.com"
        payload = b"AAA" + host + b"BBB"
        fake = DpiBypass._make_fake(payload, 3, host)
        self.assertEqual(fake[:3], b"AAA")
        self.assertEqual(fake[3 + 11:], b"BBB")

    def test_sni_replaced(self):
        host = b"example.com"
        payload = b"AAA" + host + b"BBB"
        fake = DpiBypass._make_fake(payload, 3, host)
        self.assertNotEqual(fake[3:14], host)


if __name__ == "__main__":
    unittest.main()