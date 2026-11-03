import os
import subprocess
import sys
from unittest.mock import Mock

from django.test import SimpleTestCase

from .proxy import UnixProxy


class UnixProxyTests(SimpleTestCase):
    def setUp(self):
        self.upstream = Mock(return_value=[b"ok"])
        self.proxy = UnixProxy(self.upstream)
        self.start_response = Mock()

    def test_unix_socket_preserves_client_address_for_pat_authorization(self):
        for address in ("172.28.0.112", "2001:db8::1"):
            with self.subTest(address=address):
                environ = {
                    "REMOTE_ADDR": "", "HTTP_X_REAL_IP": address,
                    "HTTP_X_FORWARDED_FOR": "203.0.113.1",
                }
                self.assertEqual(self.proxy(environ, self.start_response), [b"ok"])
                self.assertEqual(environ["REMOTE_ADDR"], address)

    def test_tcp_connections_and_invalid_or_missing_addresses_fail_closed(self):
        for environ in (
            {"REMOTE_ADDR": "127.0.0.1", "HTTP_X_REAL_IP": "172.28.0.112"},
            {"REMOTE_ADDR": "172.28.0.112", "HTTP_X_REAL_IP": "172.28.0.112"},
            {"REMOTE_ADDR": ""},
            {"HTTP_X_REAL_IP": "172.28.0.112, 203.0.113.1"},
            {"HTTP_X_REAL_IP": "invalid"},
        ):
            with self.subTest(environ=environ):
                self.assertEqual(
                    self.proxy(environ, self.start_response),
                    [b"Invalid proxy connection.\n"],
                )
                self.assertEqual(self.start_response.call_args.args[0], "400 Bad Request")
        self.upstream.assert_not_called()

    def test_production_entry_point_requires_persistent_secret_and_web_debug_off(self):
        for secret, debug, accepted in (
            ("", "2", False),
            ("CHANGE_ME", "2", False),
            ("fictitious-test-secret", "1", False),
            ("fictitious-test-secret", "2", True),
            ("fictitious-test-secret", "", True),
        ):
            with self.subTest(secret_set=bool(secret), debug=debug):
                result = subprocess.run(
                    [sys.executable, "-c", "import dnsgrid.production_wsgi"],
                    env={
                        **os.environ,
                        "DNSGRID_SECRET_KEY": secret,
                        "DNSGRID_DEBUG": debug,
                    },
                    capture_output=True, text=True, timeout=15,
                )
                self.assertEqual(result.returncode == 0, accepted, result.stderr)
