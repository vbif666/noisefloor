"""
Определение собственного IPv6 и выбор адреса для прослушивания.

Адрес по умолчанию должен быть глобальным: fe80::, ULA и loopback снаружи
недоступны, и вписанные в Endpoint они дали бы клиентам нерабочий конфиг.
"""
import unittest
from unittest import mock

from app import bootstrap, tls_serve


def _socket_with(addr):
    sock = mock.MagicMock()
    sock.__enter__.return_value = sock
    sock.getsockname.return_value = (addr, 0, 0, 0)
    return sock


class DetectIpv6Tests(unittest.TestCase):
    def _detect(self, addr):
        with mock.patch.object(bootstrap.socket, "socket", return_value=_socket_with(addr)):
            return bootstrap._detect_public_ipv6()

    def test_global_address_is_returned(self):
        self.assertEqual(self._detect("2a03:6f00:a::432b"), "2a03:6f00:a::432b")

    def test_link_local_ula_and_loopback_are_not_public(self):
        for addr in ("fe80::1", "fd12:3456::1", "::1"):
            with self.subTest(addr=addr):
                self.assertEqual(self._detect(addr), "")

    def test_zone_id_is_dropped(self):
        self.assertEqual(self._detect("2a03:6f00:a::432b%eth0"), "2a03:6f00:a::432b")

    def test_no_ipv6_route_gives_empty(self):
        with mock.patch.object(bootstrap.socket, "socket", side_effect=OSError("unreachable")):
            self.assertEqual(bootstrap._detect_public_ipv6(), "")


class ListenHostTests(unittest.TestCase):
    def _probe(self, bind_error=None):
        probe = mock.MagicMock()
        probe.__enter__.return_value = probe
        if bind_error:
            probe.bind.side_effect = bind_error
        return probe

    def test_explicit_host_is_untouched(self):
        for host in ("127.0.0.1", "::", "203.0.113.5"):
            self.assertEqual(tls_serve.listen_host(host), host)

    def test_no_ipv6_in_python_keeps_ipv4(self):
        with mock.patch.object(tls_serve.socket, "has_ipv6", False):
            self.assertEqual(tls_serve.listen_host("0.0.0.0"), "0.0.0.0")

    def test_v6only_sysctl_keeps_ipv4(self):
        # bindv6only=1: слушатель на :: перестал бы принимать IPv4.
        with mock.patch.object(tls_serve.socket, "has_ipv6", True), \
                mock.patch("builtins.open", mock.mock_open(read_data="1\n")):
            self.assertEqual(tls_serve.listen_host("0.0.0.0"), "0.0.0.0")

    def test_dual_stack_host_switches_to_double_stack(self):
        with mock.patch.object(tls_serve.socket, "has_ipv6", True), \
                mock.patch("builtins.open", mock.mock_open(read_data="0\n")), \
                mock.patch.object(tls_serve.socket, "socket", return_value=self._probe()):
            self.assertEqual(tls_serve.listen_host("0.0.0.0"), "::")

    def test_failed_probe_keeps_ipv4(self):
        with mock.patch.object(tls_serve.socket, "has_ipv6", True), \
                mock.patch("builtins.open", mock.mock_open(read_data="0\n")), \
                mock.patch.object(tls_serve.socket, "socket",
                                  return_value=self._probe(OSError("no ipv6"))):
            self.assertEqual(tls_serve.listen_host("0.0.0.0"), "0.0.0.0")


class DualStackSocketTests(unittest.TestCase):
    """Настоящий сокет: подмена socket в других тестах не видит V6ONLY,
    который asyncio ставит сам при host="::"."""

    def test_accepts_both_ipv4_and_ipv6(self):
        import socket
        try:
            server = tls_serve.bind_dual_stack(0)
        except OSError:
            self.skipTest("на хосте нет IPv6")
        self.addCleanup(server.close)
        port = server.getsockname()[1]
        for family, addr in ((socket.AF_INET, "127.0.0.1"), (socket.AF_INET6, "::1")):
            with self.subTest(addr=addr):
                with socket.socket(family) as client:
                    client.settimeout(2)
                    client.connect((addr, port))
                    conn, _ = server.accept()
                    conn.close()


if __name__ == "__main__":
    unittest.main()
