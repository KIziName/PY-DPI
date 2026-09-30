"""Тесты HTTP-парсера."""
import unittest
from config import CRLF
from dpi import DpiBypass


def mk_http(host=b"example.com"):
    return b"GET / HTTP/1.1" + CRLF + b"Host: " + host + CRLF + CRLF


class TestHttpHost(unittest.TestCase):

    def test_simple(self):
        self.assertEqual(DpiBypass._http_host(mk_http())[1], b"example.com")

    def test_with_port(self):
        self.assertEqual(
            DpiBypass._http_host(mk_http(b"a.com:8080"))[1], b"a.com")

    def test_ipv6(self):
        self.assertEqual(
            DpiBypass._http_host(mk_http(b"[::1]:443"))[1], b"[::1]")

    def test_trailing_spaces(self):
        req = (b"GET / HTTP/1.1" + CRLF
               + b"Host:   a.com   " + CRLF + CRLF)
        self.assertEqual(DpiBypass._http_host(req)[1], b"a.com")

    def test_case_insensitive(self):
        req = b"GET / HTTP/1.1" + CRLF + b"HOST: a.com" + CRLF + CRLF
        self.assertEqual(DpiBypass._http_host(req)[1], b"a.com")

    def test_missing(self):
        self.assertIsNone(DpiBypass._http_host(
            b"GET / HTTP/1.1" + CRLF + CRLF))

    def test_empty(self):
        self.assertIsNone(DpiBypass._http_host(
            b"GET / HTTP/1.1" + CRLF + b"Host:" + CRLF + CRLF))

    def test_truncated(self):
        self.assertIsNone(DpiBypass._http_host(
            b"GET / HTTP/1.1" + CRLF + b"Host: exam"))


class TestHttpMethod(unittest.TestCase):

    def test_all_methods(self):
        for m in (b"GET", b"POST", b"HEAD", b"PUT", b"DELETE",
                  b"OPTIONS", b"PATCH", b"CONNECT", b"TRACE", b"PRI"):
            self.assertTrue(DpiBypass._is_http_request_start(m + b" "))

    def test_not_method(self):
        self.assertFalse(DpiBypass._is_http_request_start(b"GARBAGE"))

    def test_partial(self):
        self.assertTrue(DpiBypass._is_http_request_partial(b"G"))
        self.assertTrue(DpiBypass._is_http_request_partial(b"GET"))


if __name__ == "__main__":
    unittest.main()