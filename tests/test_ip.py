"""Тесты IP-фильтра."""
import unittest

from bypass import _ip_is_local


class TestIpIsLocal(unittest.TestCase):

    def test_local_v4(self):
        for ip in ("127.0.0.1", "192.168.1.1", "10.0.0.1",
                   "172.16.0.1", "169.254.1.1"):
            self.assertTrue(_ip_is_local(ip, True), ip)

    def test_public_v4(self):
        for ip in ("8.8.8.8", "1.1.1.1", "142.250.0.1"):
            self.assertFalse(_ip_is_local(ip, True), ip)

    def test_local_v6(self):
        for ip in ("::1", "fe80::1", "fc00::1"):
            self.assertTrue(_ip_is_local(ip, False), ip)

    def test_invalid_is_local(self):
        self.assertTrue(_ip_is_local("not-an-ip", True))

    def test_cache_same_result(self):
        self.assertEqual(_ip_is_local("8.8.8.8", True),
                         _ip_is_local("8.8.8.8", True))


if __name__ == "__main__":
    unittest.main()