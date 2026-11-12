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

    def test_random_label_not_repeating(self):
        rep1 = DpiBypass._fake_sni(20, b"com")
        rep2 = DpiBypass._fake_sni(20, b"com")
        self.assertNotEqual(rep1, rep2)

    def test_label_is_lowercase_alpha(self):
        for _ in range(10):
            rep = DpiBypass._fake_sni(20, b"com")
            label, _, tld = rep.rpartition(b".")
            self.assertTrue(all(97 <= c <= 122 for c in label), label)
            self.assertEqual(tld, b"com")

    def test_not_all_a(self):
        reps = [DpiBypass._fake_sni(20, b"com") for _ in range(20)]
        all_a = [r for r in reps if r.rpartition(b".")[0] == b"a" * 16]
        self.assertEqual(all_a, [])

    def test_too_short_for_ru(self):
        self.assertIsNone(DpiBypass._fake_sni(0, b"ru"))
        self.assertIsNone(DpiBypass._fake_sni(3, b"ru"))

    def test_too_short_for_com(self):
        self.assertIsNone(DpiBypass._fake_sni(4, b"com"))
        self.assertIsNone(DpiBypass._fake_sni(3, b"com"))

    def test_min_length_boundaries(self):
        rep = DpiBypass._fake_sni(4, b"ru")
        self.assertIsNotNone(rep)
        self.assertEqual(len(rep), 4)
        self.assertTrue(rep.endswith(b".ru"))

        self.assertIsNone(DpiBypass._fake_sni(3, b"ru"))

        rep = DpiBypass._fake_sni(5, b"com")
        self.assertIsNotNone(rep)
        self.assertEqual(len(rep), 5)
        self.assertTrue(rep.endswith(b".com"))

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

    def test_sni_is_random_com(self):
        host = b"example.com"
        fake = DpiBypass._make_fake(host, 0, host, b"com")
        self.assertEqual(len(fake), 11)
        self.assertTrue(fake.endswith(b".com"))
        self.assertNotEqual(fake, host)

    def test_sni_is_random_ru(self):
        host = b"example.com"
        fake = DpiBypass._make_fake(host, 0, host, b"ru")
        self.assertEqual(len(fake), 11)
        self.assertTrue(fake.endswith(b".ru"))
        self.assertNotEqual(fake, host)

    def test_too_short_returns_none(self):
        host = b"t.me"
        payload = host
        self.assertIsNone(DpiBypass._make_fake(payload, 0, host, b"com"))
        fake = DpiBypass._make_fake(payload, 0, host, b"ru")
        self.assertIsNotNone(fake)
        self.assertEqual(len(fake), 4)
        self.assertTrue(fake.endswith(b".ru"))


class TestNoRealDomainInFake(unittest.TestCase):
    """Регрессия: реальные домены не должны попадать в фейк."""

    def test_yandex_ru_not_used_as_fake(self):
        fake = DpiBypass._make_fake(
            b"www.yandex.ru", 0, b"www.yandex.ru", b"com")
        self.assertNotEqual(fake, b"www.yandex.ru")
        self.assertEqual(len(fake), 13)
        self.assertTrue(fake.endswith(b".com"))

    def test_yandex_ru_with_ru_tld(self):
        fake = DpiBypass._make_fake(
            b"www.yandex.ru", 0, b"www.yandex.ru", b"ru")
        self.assertNotEqual(fake, b"www.yandex.ru")
        self.assertEqual(len(fake), 13)
        self.assertTrue(fake.endswith(b".ru"))

    def test_fake_never_matches_real(self):
        # 200 итераций: для label_len==1 (x.com) вероятность коллизии 1/26,
        # за 200 итераций старый код упал бы с шансом ~99.96%.
        for host in (b"discord.com", b"www.youtube.com", b"x.com",
                     b"github.com", b"api.telegram.org",
                     b"www.yandex.ru"):
            for _ in range(200):
                fake = DpiBypass._make_fake(host, 0, host, b"com")
                if fake is not None:
                    self.assertNotEqual(
                        fake.lower(), host.lower(),
                        f"collision with {host!r}")

    def test_exclude_guarantees_difference(self):
        # Прямой детерминированный тест на exclude: для всех 26 возможных
        # 1-буквенных доменов фейк не должен совпасть с реальным.
        for c in range(ord('a'), ord('z') + 1):
            host = bytes([c]) + b".com"
            for _ in range(50):
                rep = DpiBypass._fake_sni(5, b"com", exclude=host)
                self.assertIsNotNone(rep)
                self.assertNotEqual(rep.lower(), host.lower(),
                                    f"exclude failed for {host!r}")

    def test_fake_structure(self):
        for host in (b"discord.com", b"www.youtube.com",
                     b"api.telegram.org", b"www.yandex.ru"):
            fake = DpiBypass._make_fake(host, 0, host, b"com")
            if fake is not None:
                label, _, tld = fake.rpartition(b".")
                self.assertEqual(tld, b"com")
                self.assertEqual(len(label), len(host) - 4)
                self.assertTrue(all(97 <= c <= 122 for c in label), label)


if __name__ == "__main__":
    unittest.main()
