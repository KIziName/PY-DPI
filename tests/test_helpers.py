"""Тесты хелперов: midsld, fake_sni, make_fake."""
import unittest

from bypass import DpiBypass


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

    def test_length_all_tlds(self):
        for tld in (b"ru", b"com", b"net", b"org"):
            for n in range(len(tld) + 2, 40):
                rep = DpiBypass._fake_sni(n, tld)
                self.assertIsNotNone(rep, (n, tld))
                self.assertEqual(len(rep), n, (n, tld, rep))

    def test_tld_suffix(self):
        for tld in (b"ru", b"com", b"net"):
            rep = DpiBypass._fake_sni(20, tld)
            self.assertTrue(rep.endswith(b"." + tld), rep)

    def test_always_a_prefix(self):
        for n in (6, 11, 15, 30):
            rep = DpiBypass._fake_sni(n, b"com")
            self.assertEqual(rep, b"a" * (n - 4) + b".com")

    def test_too_short_for_ru(self):
        self.assertIsNone(DpiBypass._fake_sni(0, b"ru"))
        self.assertIsNone(DpiBypass._fake_sni(3, b"ru"))

    def test_too_short_for_com(self):
        self.assertIsNone(DpiBypass._fake_sni(4, b"com"))
        self.assertIsNone(DpiBypass._fake_sni(3, b"com"))

    def test_min_length_boundaries(self):
        # минимум для "ru" — 4 ("a.ru"), для "com" — 5 ("a.com")
        self.assertEqual(DpiBypass._fake_sni(4, b"ru"), b"a.ru")
        self.assertIsNone(DpiBypass._fake_sni(3, b"ru"))
        self.assertEqual(DpiBypass._fake_sni(5, b"com"), b"a.com")
        self.assertIsNone(DpiBypass._fake_sni(4, b"com"))


class TestMakeFake(unittest.TestCase):

    def test_preserves_length(self):
        host = b"example.com"
        payload = b"AAA" + host + b"BBB"
        fake = DpiBypass._make_fake(payload, 3, host, b"com")
        self.assertIsNotNone(fake)
        self.assertEqual(len(fake), len(payload))

    def test_prefix_suffix_untouched(self):
        host = b"example.com"
        payload = b"AAA" + host + b"BBB"
        fake = DpiBypass._make_fake(payload, 3, host, b"com")
        self.assertEqual(fake[:3], b"AAA")
        self.assertEqual(fake[3 + 11:], b"BBB")

    def test_sni_replaced(self):
        host = b"example.com"
        payload = b"AAA" + host + b"BBB"
        fake = DpiBypass._make_fake(payload, 3, host, b"com")
        self.assertNotEqual(fake[3:14], host)

    def test_sni_is_a_com(self):
        host = b"example.com"  # 11 байт
        payload = host
        fake = DpiBypass._make_fake(payload, 0, host, b"com")
        self.assertEqual(fake, b"aaaaaaa.com")

    def test_sni_is_a_ru(self):
        host = b"example.com"  # 11 байт
        fake = DpiBypass._make_fake(host, 0, host, b"ru")
        self.assertEqual(fake, b"aaaaaaaa.ru")

    def test_too_short_returns_none(self):
        host = b"t.me"  # 4 байта
        payload = host
        self.assertIsNone(DpiBypass._make_fake(payload, 0, host, b"com"))
        # с "ru" — влезает: "a.ru"
        self.assertEqual(
            DpiBypass._make_fake(payload, 0, host, b"ru"), b"a.ru")


if __name__ == "__main__":
    unittest.main()
