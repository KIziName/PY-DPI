"""Тесты распознавания доменов и детекта."""
import unittest
from config import CRLF
from dpi import DpiBypass
from tests.test_tls import mk_client_hello


def mk_http(host=b"example.com"):
    return b"GET / HTTP/1.1" + CRLF + b"Host: " + host + CRLF + CRLF


class TestHostMatches(unittest.TestCase):

    def setUp(self):
        self.bp = DpiBypass(["example.com", "x.com"], "split", lambda m: None)

    def test_exact(self):
        self.assertTrue(self.bp._host_matches(b"example.com"))

    def test_subdomain(self):
        self.assertTrue(self.bp._host_matches(b"a.b.example.com"))

    def test_case_and_dot(self):
        self.assertTrue(self.bp._host_matches(b"EXAMPLE.COM."))

    def test_not_match(self):
        self.assertFalse(self.bp._host_matches(b"other.com"))

    def test_no_false_positive_prefix(self):
        self.assertFalse(self.bp._host_matches(b"notexample.com"))

    def test_no_false_positive_suffix(self):
        self.assertFalse(self.bp._host_matches(b"example.com.evil.org"))


class TestDetect(unittest.TestCase):

    def setUp(self):
        self.bp = DpiBypass(["example.com"], "split", lambda m: None)

    def test_tls_match(self):
        kind, data = self.bp._detect_host(mk_client_hello())
        self.assertEqual(kind, "match")
        self.assertEqual(data[1], b"example.com")

    def test_tls_incomplete(self):
        ch = mk_client_hello()
        self.assertEqual(self.bp._detect_host(ch[:10])[0], "incomplete")

    def test_http_match(self):
        kind, data = self.bp._detect_host(mk_http())
        self.assertEqual(kind, "match")
        self.assertEqual(data[1], b"example.com")

    def test_http_incomplete(self):
        self.assertEqual(
            self.bp._detect_host(b"GET / HTTP/1.1" + CRLF + b"X: y")[0],
            "incomplete")

    def test_garbage(self):
        self.assertEqual(self.bp._detect_host(b"\xff\xfe")[0], "none")

    def test_empty(self):
        self.assertEqual(self.bp._detect_host(b"")[0], "none")


if __name__ == "__main__":
    unittest.main()