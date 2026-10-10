import json
import subprocess
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from django.core.exceptions import ValidationError
from django.test import SimpleTestCase, override_settings

from .dns_sftp import deliver, quote, read_result, validate_delivery, validate_destination, validate_remote_path


@override_settings(DNSGRID_DNS_SFTP_IDENTITY_FILE="/etc/dnsgrid/key",
                   DNSGRID_DNS_SFTP_KNOWN_HOSTS="/etc/dnsgrid/known_hosts")
class SFTPTests(SimpleTestCase):
    def setUp(self):
        self.config = SimpleNamespace(
            dns_sftp_host="nas.example.test", dns_sftp_user="dnsgrid",
            dns_sftp_port=2222, dns_sftp_inbox="/incoming/inbox",
            dns_sftp_outbox="/results/outbox",
        )
        self.delivery = "dnsgrid-2026100900-" + "a" * 32
        self.manifest = {
            "generation": "dnsgrid-2026100900", "serial": 2026100900,
            "zones": [{"filename": "example.test"}],
        }

    @patch("inventory.dns_sftp.subprocess.run", return_value=SimpleNamespace(returncode=0))
    def test_batch_manifest_last_and_rename_with_strict_key_only_transport(self, run):
        status, _ = deliver(self.config, Path('/local/a "quoted" [dir]'), self.manifest, self.delivery)
        self.assertEqual(status, "delivered")
        argv = run.call_args.args[0]
        self.assertEqual(argv[0], "/usr/bin/sftp")
        self.assertEqual(argv[-1], "dnsgrid@nas.example.test")
        for option in ("BatchMode=yes", "StrictHostKeyChecking=yes", "IdentitiesOnly=yes"):
            self.assertIn(option, argv)
        self.assertFalse(run.call_args.kwargs["shell"])
        self.assertEqual(run.call_args.kwargs["timeout"], 120)
        batch = run.call_args.kwargs["input"].decode().splitlines()
        self.assertTrue(batch[0].startswith("mkdir "))
        self.assertIn(".partial", batch[0])
        self.assertIn("example.test", batch[1])
        self.assertIn("manifest.json", batch[-2])
        self.assertTrue(batch[-1].startswith("rename "))
        self.assertNotIn("manifest", batch[-1])
        self.assertIn(r'\"quoted\" [dir]', batch[1])

    @patch("inventory.dns_sftp.subprocess.run")
    def test_failures_never_confirm_installation_or_leak_output(self, run):
        run.side_effect = subprocess.TimeoutExpired("sftp", 120, output=b"secret")
        self.assertEqual(deliver(self.config, Path("/local"), self.manifest, self.delivery)[0], "unconfirmed")
        run.side_effect = OSError("secret")
        status, summary = deliver(self.config, Path("/local"), self.manifest, self.delivery)
        self.assertEqual(status, "failure")
        self.assertNotIn("secret", summary)
        run.side_effect = None
        run.return_value = SimpleNamespace(returncode=255)
        self.assertEqual(deliver(self.config, Path("/local"), self.manifest, self.delivery)[0], "unconfirmed")

    def test_identifiers_destinations_and_paths_reject_injection(self):
        for path in ("/", "/a/../b", "/a/./b", "/a//b", "relative", "/a\nput evil"):
            with self.assertRaises(ValidationError):
                validate_remote_path(path)
        for delivery in ("../escape", self.delivery + ".partial", self.delivery.upper()):
            with self.assertRaises(ValidationError):
                validate_delivery(delivery, 2026100900)
        for host, user, port in (("-oevil", "dns", 22), ("a;evil", "dns", 22),
                                 ("nas", "-evil", 22), ("nas", "dns", True),
                                 ("fe80::1%eth0", "dns", 22)):
            with self.assertRaises(ValidationError):
                validate_destination(host, user, port)
        self.assertEqual(quote('/a"b\\c*[d]?'), r'"/a\"b\\c*[d]?"')

    def test_result_is_bound_to_delivery_and_serial_and_never_displays_remote_summary(self):
        result = {
            "delivery": self.delivery, "serial": 2026100900, "status": "installed",
            "timestamp": "2026-10-09T23:00:00+00:00", "summary": "<secret>",
        }
        def transfer(config, batch, download=False):
            # The generated local destination is the last quoted batch token.
            target = Path(batch.split('"')[-2])
            target.write_text(json.dumps(result))
            return 0
        with patch("inventory.dns_sftp._run", side_effect=transfer):
            status, summary = read_result(self.config, self.delivery, 2026100900)
            self.assertEqual(status, "installed")
            self.assertNotIn("secret", summary)
            for field, bad in (("delivery", "dnsgrid-2026100900-" + "b" * 32),
                               ("serial", True), ("status", "success"),
                               ("timestamp", "2026-10-09T23:00:00"),
                               ("summary", "a" * 513)):
                original = result[field]
                result[field] = bad
                self.assertEqual(read_result(self.config, self.delivery, 2026100900)[0], "invalid")
                result[field] = original

    @patch("inventory.dns_sftp._run", return_value=1)
    def test_missing_result_remains_pending(self, run):
        self.assertEqual(read_result(self.config, self.delivery, 2026100900)[0], "pending")

    @patch("inventory.dns_sftp.subprocess.run", return_value=SimpleNamespace(returncode=1))
    def test_receipt_download_has_bandwidth_and_time_bounds(self, run):
        self.assertEqual(read_result(self.config, self.delivery, 2026100900)[0], "pending")
        self.assertEqual(run.call_args.args[0][1:3], ["-l", "64"])
        self.assertEqual(run.call_args.kwargs["timeout"], 120)

    def test_hostile_receipt_symlink_oversize_duplicate_keys_and_controls(self):
        raw = b"{}"
        symlink = False
        def transfer(config, batch, download=False):
            target = Path(batch.split('"')[-2])
            if symlink:
                target.symlink_to("/dev/null")
            else:
                target.write_bytes(raw)
            return 0
        with patch("inventory.dns_sftp._run", side_effect=transfer):
            for raw in (
                b"a" * 8193,
                b'{"delivery":"a","delivery":"b"}',
                b"[" * 2000 + b"]" * 2000,
            ):
                self.assertEqual(read_result(self.config, self.delivery, 2026100900)[0], "invalid")
            symlink = True
            self.assertEqual(read_result(self.config, self.delivery, 2026100900)[0], "pending")

    @patch("inventory.dns_sftp.subprocess.run")
    def test_invalid_key_paths_never_start_transport(self, run):
        for key, value in (
            ("DNSGRID_DNS_SFTP_IDENTITY_FILE", "relative"),
            ("DNSGRID_DNS_SFTP_KNOWN_HOSTS", '/etc/a"evil'),
            ("DNSGRID_DNS_SFTP_KNOWN_HOSTS", "/etc/a b"),
        ):
            with override_settings(**{key: value}), self.assertRaises(ValidationError):
                deliver(self.config, Path("/local"), self.manifest, self.delivery)
        run.assert_not_called()

    def test_literal_batch_paths_with_local_openssh_server(self):
        server = Path("/usr/lib/openssh/sftp-server")
        if not server.is_file() or not Path("/usr/bin/sftp").is_file():
            self.skipTest("Local OpenSSH SFTP client/server unavailable.")
        with tempfile.TemporaryDirectory(prefix="dnsgrid-sftp-") as directory:
            root = Path(directory)
            source = root / 'zone "quoted" [literal]*?.test'
            source.write_bytes(b"literal path test\n")
            partial = root / "inbox [literal]*.partial"
            destination = root / "inbox [literal]*"
            batch = "\n".join([
                f"mkdir {quote(partial)}",
                f"put {quote(source)} {quote(partial / 'zone.test')}",
                f"put {quote(source)} {quote(partial / 'manifest.json')}",
                f"rename {quote(partial)} {quote(destination)}",
                f"get {quote(destination / 'zone.test')} {quote(root / 'receipt')}",
            ]) + "\n"
            result = subprocess.run(
                ["/usr/bin/sftp", "-D", str(server), "-b", "-"],
                input=batch.encode(), capture_output=True, timeout=10, shell=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            self.assertEqual((destination / "zone.test").read_bytes(), source.read_bytes())
            self.assertEqual((root / "receipt").read_bytes(), source.read_bytes())
            self.assertFalse(partial.exists())
