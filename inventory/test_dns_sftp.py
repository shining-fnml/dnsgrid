import fcntl
import json
import os
import runpy
import subprocess
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from django.core.exceptions import ValidationError
from django.test import SimpleTestCase, override_settings

from .dns_sftp import deliver, quote, read_result, validate_delivery, validate_destination, validate_remote_path
from .dns_diagnostics import OUTPUT_LIMIT, capture_output, log, sanitized_output


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

    def test_uint32_delivery_identifiers_and_receipts(self):
        for serial in (0, 42, 1692746706, 2026023000, 4294967295):
            delivery = f"dnsgrid-{serial}-" + "a" * 32
            validate_delivery(delivery, serial)
            result = {
                "delivery": delivery, "serial": serial, "status": "installed",
                "timestamp": "2026-10-09T23:00:00+00:00", "summary": "Installed",
            }

            def transfer(config, batch, download=False):
                Path(batch.split('"')[-2]).write_text(json.dumps(result))
                return 0

            with patch("inventory.dns_sftp._run", side_effect=transfer):
                self.assertEqual(read_result(self.config, delivery, serial)[0], "installed")

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

    @patch("inventory.dns_sftp._run")
    def test_all_delivery_status_messages_are_english(self, run):
        for outcome, status, summary in (
            (0, "delivered", "Delivered, awaiting NAS processing. File installation is not yet confirmed."),
            (255, "unconfirmed", "Delivery unconfirmed: SFTP interrupted or failed. Check NAS result."),
            (subprocess.TimeoutExpired("sftp", 120), "unconfirmed",
             "Delivery unconfirmed: SFTP timed out. Check NAS result before retrying."),
            (OSError("secret"), "failure", "Unable to start SFTP; check local configuration."),
        ):
            with self.subTest(outcome=outcome):
                run.side_effect = outcome if isinstance(outcome, Exception) else None
                run.return_value = outcome
                self.assertEqual(
                    deliver(self.config, Path("/local"), self.manifest, self.delivery),
                    (status, summary),
                )

    def test_all_result_status_messages_are_english(self):
        result = {
            "delivery": self.delivery, "serial": 2026100900, "status": "installed",
            "timestamp": "2026-10-09T23:00:00+00:00", "summary": "<secret>",
        }

        def transfer(config, batch, download=False):
            Path(batch.split('"')[-2]).write_text(json.dumps(result))
            return 0

        with patch("inventory.dns_sftp._run", side_effect=transfer):
            for status, summary in (
                ("installed", "Files installed on the NAS; zone loading not verified."),
                ("already_installed", "Files already installed on the NAS; zone loading not verified."),
                ("failed", "NAS installation failed; consult protected local diagnostics."),
                ("invalid", "Invalid NAS result; no installation confirmed."),
            ):
                with self.subTest(status=status):
                    result["status"] = status
                    self.assertEqual(read_result(self.config, self.delivery, 2026100900), (status, summary))

        with patch("inventory.dns_sftp._run") as run:
            for outcome, summary in (
                (1, "Result unavailable: delivery completed or unconfirmed, awaiting NAS processing."),
                (subprocess.TimeoutExpired("sftp", 120), "NAS result read unconfirmed; retry the check."),
                (OSError("secret"), "NAS result read unconfirmed; retry the check."),
            ):
                with self.subTest(outcome=outcome):
                    run.side_effect = outcome if isinstance(outcome, Exception) else None
                    run.return_value = outcome
                    self.assertEqual(read_result(self.config, self.delivery, 2026100900), ("pending", summary))

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

    @override_settings(DNSGRID_DIAGNOSTICS=True)
    def test_diagnostic_success_logs_plans_and_confirmation_without_quiet_mode(self):
        def transfer(*args, **kwargs):
            os.write(kwargs["stdout"], b"sftp> put secret-zone-content\n")
            os.write(kwargs["stderr"], b"remote banner with ******")
            return SimpleNamespace(returncode=0)

        with patch("inventory.dns_sftp.subprocess.run", side_effect=transfer) as run:
            with self.assertLogs("dnsgrid.delivery", level="DEBUG") as output:
                status, summary = deliver(self.config, Path("/local"), self.manifest, self.delivery)
        self.assertEqual(status, "delivered")
        self.assertIn("not yet confirmed", summary)
        self.assertNotIn("-q", run.call_args.args[0])
        self.assertFalse(run.call_args.kwargs["shell"])
        self.assertEqual(run.call_args.kwargs["timeout"], 120)
        text = "\n".join(output.output)
        for expected in (
            self.delivery, self.manifest["generation"], "nas.example.test", "2222",
            "create partial directory", "upload zone", "example.test",
            "upload manifest last", "atomic final rename", "not yet confirmed",
            "batch confirmed", "exit_status", "elapsed_seconds", "stdout", "stderr",
            "NAS installation not confirmed", "[redacted]",
        ):
            self.assertIn(expected, text)
        for secret in ("secret-zone-content", "******", "/etc/dnsgrid/key", "/etc/dnsgrid/known_hosts"):
            self.assertNotIn(secret, text)

    @override_settings(DNSGRID_DIAGNOSTICS=False)
    @patch("inventory.dns_sftp.subprocess.run", return_value=SimpleNamespace(returncode=0))
    def test_normal_and_level_one_keep_quiet_transport_and_concise_outcome(self, run):
        with self.assertLogs("dnsgrid.delivery", level="DEBUG") as output:
            deliver(self.config, Path("/local"), self.manifest, self.delivery)
        self.assertIn("-q", run.call_args.args[0])
        self.assertEqual(run.call_args.kwargs["stdout"], subprocess.DEVNULL)
        self.assertEqual(run.call_args.kwargs["stderr"], subprocess.DEVNULL)
        self.assertEqual(len(output.output), 1)
        self.assertIn(self.delivery, output.output[0])
        self.assertNotIn("SFTP plan", output.output[0])

    @override_settings(DNSGRID_DIAGNOSTICS=True)
    def test_diagnostic_nonzero_timeout_and_startup_failure_are_safe(self):
        for outcome, expected, status in (
            (255, "batch unconfirmed", "unconfirmed"),
            (subprocess.TimeoutExpired("secret-command", 120, output=b"private key",
                                       stderr=b"raw receipt"), "timeout after 120 seconds", "unconfirmed"),
            (OSError("credentials=secret"), "startup failure", "failure"),
        ):
            def transfer(*args, **kwargs):
                os.write(kwargs["stderr"], b"\x1b[31mPermission denied (publickey). secret\n")
                if isinstance(outcome, Exception):
                    raise outcome
                return SimpleNamespace(returncode=outcome)

            with self.subTest(outcome=expected):
                with patch("inventory.dns_sftp.subprocess.run", side_effect=transfer):
                    with self.assertLogs("dnsgrid.delivery", level="DEBUG") as output:
                        result = deliver(self.config, Path("/local"), self.manifest, self.delivery)
                self.assertEqual(result[0], status)
                text = "\n".join(output.output)
                self.assertIn(expected, text)
                self.assertIn("permission denied", text)
                self.assertIn(self.delivery, text)
                self.assertIn("elapsed_seconds", text)
                self.assertIn('"exit_status": "255"' if outcome == 255 else
                              '"exit_status": "unavailable"', text)
                for secret in ("secret", "private key", "raw receipt", "\x1b"):
                    self.assertNotIn(secret, text)
                    self.assertNotIn(secret, result[1])

    @override_settings(DNSGRID_DIAGNOSTICS=True)
    def test_receipt_trace_does_not_log_raw_receipt_or_summary(self):
        def transfer(*args, **kwargs):
            batch = kwargs["input"].decode()
            Path(batch.split('"')[-2]).write_text(json.dumps({
                "delivery": self.delivery, "serial": 2026100900, "status": "installed",
                "timestamp": "2026-10-09T23:00:00+00:00", "summary": "private receipt",
            }))
            os.write(kwargs["stdout"], b'{"summary":"private receipt"}')
            return SimpleNamespace(returncode=0)

        with patch("inventory.dns_sftp.subprocess.run", side_effect=transfer):
            with self.assertLogs("dnsgrid.delivery", level="DEBUG") as output:
                status, summary = read_result(self.config, self.delivery, 2026100900)
        self.assertEqual(status, "installed")
        text = "\n".join(output.output)
        self.assertIn("receipt download planned", text)
        self.assertIn("receipt download confirmed", text)
        self.assertIn("Validated NAS receipt", text)
        self.assertNotIn("private receipt", text + summary)

    def test_capture_and_sanitized_output_are_bounded_and_redact_all_arbitrary_text(self):
        with capture_output() as (pipes, captured):
            for pipe in pipes:
                for _ in range(32):
                    os.write(pipe, b"x" * OUTPUT_LIMIT)
        for raw, total in captured:
            self.assertEqual(len(raw), OUTPUT_LIMIT)
            self.assertEqual(total, OUTPUT_LIMIT * 32)
            result = sanitized_output(raw, total)
            self.assertTrue(result["truncated"])
            self.assertLess(len(str(result)), 1024)
        raw = (b"-----BEGIN OPENSSH PRIVATE KEY-----\nprivate\n"
               b"token=secret ****** IN TXT secret\n"
               b'{"zones": [], "summary": "private receipt"}\x1b[2J\r\n'
               b"Host key verification failed.")
        text = str(sanitized_output(raw, len(raw)))
        self.assertIn("host key verification failed", text)
        for secret in ("PRIVATE KEY", "private", "secret", "\x1b", "\r", "\n"):
            self.assertNotIn(secret, text)

    @override_settings(DNSGRID_DIAGNOSTICS=True)
    def test_terminal_fields_escape_controls_and_are_bounded(self):
        with self.assertLogs("dnsgrid.delivery", level="DEBUG") as output:
            log("test", detail=True, path="\x1b\r\n\u202e" + "x" * 10000)
        text = output.output[0]
        self.assertNotIn("\x1b", text)
        self.assertNotIn("\u202e", text)
        self.assertNotIn("\n", text)
        self.assertIn(r"\u001b", text)
        self.assertLess(len(text), 1200)

    def test_capture_handles_high_numbered_file_descriptors(self):
        pipe = os.pipe

        def high_pipe():
            reader, writer = pipe()
            try:
                high_reader = fcntl.fcntl(reader, fcntl.F_DUPFD, 1024)
            except OSError:
                os.close(writer)
                self.skipTest("High-numbered file descriptors unavailable.")
            finally:
                os.close(reader)
            return high_reader, writer

        with patch("inventory.dns_diagnostics.os.pipe", side_effect=high_pipe):
            with capture_output() as (pipes, captured):
                for writer in pipes:
                    os.write(writer, b"Permission denied")
        for raw, total in captured:
            self.assertEqual(raw, b"Permission denied")
            self.assertEqual(total, len(raw))

    def test_debug_levels_and_console_configuration(self):
        settings_path = Path(__file__).resolve().parent.parent / "dnsgrid" / "settings.py"
        for level in ("", "1", "2", "unexpected"):
            with self.subTest(level=level), patch.dict(os.environ, {"DNSGRID_DEBUG": level}):
                values = runpy.run_path(str(settings_path))
                self.assertEqual(values["DEBUG"], level == "1")
                self.assertEqual(values["DNSGRID_DIAGNOSTICS"], level == "2")
                configuration = values["LOGGING"]
                self.assertFalse(configuration["disable_existing_loggers"])
                console = configuration["handlers"]["delivery_console"]
                self.assertEqual(console["class"], "logging.StreamHandler")
                self.assertEqual(console["stream"], "ext://sys.stderr")
                expected = "DEBUG" if level == "2" else "INFO"
                self.assertEqual(console["level"], expected)
                logger = configuration["loggers"]["dnsgrid.delivery"]
                self.assertEqual(logger["level"], expected)
                self.assertEqual(logger["handlers"], ["delivery_console"])
                self.assertFalse(logger["propagate"])
