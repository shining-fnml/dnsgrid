import io
import json
import os
import tempfile
from pathlib import Path
from unittest.mock import patch
from concurrent.futures import ThreadPoolExecutor
from threading import Event

from django.core.exceptions import ValidationError
from django.core.management import call_command
from django.core.management.base import CommandError
from django.db import OperationalError, close_old_connections
from django.test import TestCase, TransactionTestCase

from . import dns_reset
from .dns_delivery import _lock, publish_and_deliver, retry_delivery
from .dns_serial import MAX_SERIAL, content_fingerprint
from .exporters import publish_dns_zones
from .models import Configuration, Host, Site
from .services import save_host


class DNSResetTests(TestCase):
    timestamp = 1791686400

    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        Configuration.objects.update(
            dns_export_directory=str(self.root), soa_serial=2026101004,
            dns_sftp_host="nas.example.test", dns_sftp_user="dns",
            dns_sftp_inbox="/inbox", dns_sftp_outbox="/outbox",
        )
        self.clock = patch("inventory.dns_reset.initial_serial", return_value=self.timestamp)
        self.clock.start()
        self.addCleanup(self.clock.stop)
        self.transport = patch("inventory.dns_delivery.dns_sftp.deliver",
                               return_value=("unconfirmed", "SFTP delivery unconfirmed; check NAS result."))
        self.send = self.transport.start()
        self.addCleanup(self.transport.stop)
        publish_and_deliver(str(Configuration.load().revision))
        self.old_generation = Configuration.load().dns_published_generation
        self.old_path = self.root / "generations" / self.old_generation
        self.old_attempt = json.loads((self.old_path / ".delivery.json").read_text())

    def execute(self, **changes):
        plan, token = dns_reset.preview()
        return dns_reset.reset(**{
            "timestamp": plan["timestamp"], "token": token, "confirmed": True,
            "unloaded": True, "nas_handled": True, **changes,
        })

    def recover(self):
        return dns_reset.reset(confirmed=True, unloaded=True, nas_handled=True, recover=True)

    def files(self):
        return {str(p.relative_to(self.root)): p.read_bytes()
                for p in self.root.rglob("*") if p.is_file()}

    def test_preview_is_read_only_and_lists_exact_artifacts(self):
        (self.root / ".dnsgrid-delivery.lock").unlink()
        before, config = self.files(), list(Configuration.objects.values())
        output = io.StringIO()
        call_command("reset_dns_publication", stdout=output)
        self.assertEqual(self.files(), before)
        self.assertEqual(list(Configuration.objects.values()), config)
        for text in ("READ-ONLY PREVIEW", f"2026101004 -> {self.timestamp}",
                     str(self.old_path / ".pin"), str(self.old_path / ".delivery.json"),
                     "--ack-never-loaded", "--ack-nas-handled"):
            self.assertIn(text, output.getvalue())

    def test_confirmation_and_exact_preview_are_required(self):
        for changes in ({"confirmed": False}, {"unloaded": False}, {"nas_handled": False},
                        {"token": ""}, {"token": "stale"}):
            before = self.files()
            with self.assertRaises(ValidationError):
                self.execute(**changes)
            self.assertEqual(self.files(), before)
        with self.assertRaises(CommandError):
            call_command("reset_dns_publication", confirm=True)
        self.assertEqual(Configuration.load().soa_serial, 2026101004)

    def test_reset_preserves_unrelated_data_and_all_revision_counters(self):
        for name in ("unrelated.txt", "installed.json", "transaction.json", "backup.zip"):
            (self.root / name).write_text("preserve")
        Host.objects.create(name="retained", site_id=1, row=1, column=0)
        before_config = Configuration.objects.values().get(pk=1)
        hosts, sites = list(Host.objects.values()), list(Site.objects.values())
        lock_inode = (self.root / ".dnsgrid-delivery.lock").stat().st_ino
        (self.root / "forward.zone").write_text("legacy loose test zone")
        quarantine = self.execute()
        config = Configuration.load()
        self.assertEqual(config.soa_serial, self.timestamp)
        self.assertEqual(config.dns_content_hash, content_fingerprint(config))
        self.assertEqual(config.dns_published_generation, "")
        for name, value in before_config.items():
            if name not in {"soa_serial", "dns_content_hash", "dns_published_generation"}:
                self.assertEqual(getattr(config, name), value)
        self.assertEqual(list(Host.objects.values()), hosts)
        self.assertEqual(list(Site.objects.values()), sites)
        for name in ("unrelated.txt", "installed.json", "transaction.json", "backup.zip"):
            self.assertEqual((self.root / name).read_text(), "preserve")
        self.assertEqual((self.root / ".dnsgrid-delivery.lock").stat().st_ino, lock_inode)
        self.assertFalse(self.old_path.exists())
        for name in (".pin", ".delivery.json", "manifest.json"):
            self.assertTrue((quarantine / "generations" / self.old_generation / name).is_file())
        self.assertTrue((quarantine / "forward.zone").exists())
        self.assertTrue((quarantine / "completed.json").exists())
        self.assertIsNone(self.recover())

    def test_fresh_timestamp_delivery_and_unchanged_idempotence_and_explicit_retry(self):
        self.execute()
        self.send.reset_mock()
        with self.assertRaises(OSError):
            retry_delivery(Configuration.load().revision, self.old_generation)
        self.send.assert_not_called()
        publish_and_deliver(str(Configuration.load().revision))
        self.send.assert_called_once()
        config = Configuration.load()
        self.assertEqual(config.dns_published_generation, f"dnsgrid-{self.timestamp}")
        path = self.root / "generations" / config.dns_published_generation
        attempt = json.loads((path / ".delivery.json").read_text())
        self.assertNotEqual(attempt["delivery"], self.old_attempt["delivery"])
        raw = (path / "manifest.json").read_bytes()
        publish_and_deliver(str(config.revision))
        self.send.assert_called_once()
        retry_delivery(config.revision, config.dns_published_generation)
        self.assertEqual(self.send.call_count, 2)
        self.assertEqual((path / "manifest.json").read_bytes(), raw)
        self.assertEqual(Configuration.load().soa_serial, self.timestamp)

    def test_stale_config_artifact_and_timestamp_previews(self):
        plan, token = dns_reset.preview()
        for change in ("config", "artifact", "time"):
            with self.subTest(change=change):
                if change == "config":
                    Configuration.objects.update(ttl=Configuration.load().ttl + 1)
                elif change == "artifact":
                    (self.old_path / ".pin").write_text("changed")
                with patch("inventory.dns_reset.initial_serial", return_value=(
                        self.timestamp + 901 if change == "time" else self.timestamp)):
                    with self.assertRaises(ValidationError):
                        dns_reset.reset(plan["timestamp"], token, confirmed=True,
                                        unloaded=True, nas_handled=True)
        self.assertFalse((self.root / dns_reset.JOURNAL).exists())

    def test_unsafe_paths_symlinks_and_malformed_generation_fail_without_cleanup(self):
        for name in ("unexpected.txt", ".pin", ".delivery.json", "manifest.json"):
            target = self.old_path / name
            old = target.read_bytes() if target.exists() else None
            target.write_text("malformed")
            try:
                # A plain pin is allowed, but a symlink must never be followed.
                if name == ".pin":
                    target.unlink()
                    target.symlink_to(self.root / "outside")
                with self.assertRaises((ValidationError, OSError)):
                    dns_reset.preview()
                self.assertTrue(self.old_path.is_dir())
            finally:
                target.unlink()
                if old is not None:
                    target.write_bytes(old)
        original = str(self.root)
        for directory in ("/", "", "relative", str(self.root / "..")):
            Configuration.objects.update(dns_export_directory=directory)
            with self.assertRaises((ValidationError, OSError)):
                dns_reset.preview()
        link = self.root / "linked"
        link.symlink_to(self.root, target_is_directory=True)
        Configuration.objects.update(dns_export_directory=str(link))
        with self.assertRaises(ValidationError):
            dns_reset.preview()
        Configuration.objects.update(dns_export_directory=original)

    def test_lock_contention_rejects_reset_without_deleting_lock(self):
        inode = (self.root / ".dnsgrid-delivery.lock").stat().st_ino
        with _lock(str(self.root)):
            with self.assertRaisesMessage(ValidationError, "Another"):
                self.execute()
        self.assertEqual((self.root / ".dnsgrid-delivery.lock").stat().st_ino, inode)

    def test_filesystem_partial_failure_blocks_writers_and_rolls_forward(self):
        replace = os.replace
        moves = 0

        def fail_second_move(source, target):
            nonlocal moves
            if str(target).startswith(str(self.root / ".dnsgrid-reset-")):
                moves += 1
                if moves == 2:
                    raise OSError("simulated move failure")
            return replace(source, target)

        with patch("inventory.dns_reset.os.replace", side_effect=fail_second_move):
            with self.assertRaises(OSError):
                self.execute()
        self.assertTrue((self.root / dns_reset.JOURNAL).is_file())
        self.assertEqual(Configuration.load().soa_serial, 2026101004)
        for action in (
            lambda: publish_dns_zones(str(Configuration.load().revision)),
            lambda: retry_delivery(Configuration.load().revision, self.old_generation),
            lambda: save_host(Host(name="blocked", site_id=1, row=1, column=0),
                              Configuration.load().revision),
        ):
            with self.assertRaisesMessage(ValidationError, "recovery is outstanding"):
                action()
        self.recover()
        self.assertEqual(Configuration.load().soa_serial, self.timestamp)
        self.assertFalse(self.old_path.exists())
        self.assertFalse((self.root / dns_reset.JOURNAL).exists())

    def test_database_failure_and_post_commit_journal_failure_are_recoverable(self):
        with patch("inventory.services._reset_dns_tracking", side_effect=OperationalError("DB failure")):
            with self.assertRaises(OperationalError):
                self.execute()
        self.assertFalse(self.old_path.exists())
        self.assertEqual(Configuration.load().soa_serial, 2026101004)
        replace = os.replace

        def fail_retirement(source, target):
            if str(source) == str(self.root / dns_reset.JOURNAL):
                raise OSError("journal retirement failed")
            return replace(source, target)

        with patch("inventory.dns_reset.os.replace", side_effect=fail_retirement):
            with self.assertRaises(OSError):
                self.recover()
        self.assertEqual(Configuration.load().soa_serial, self.timestamp)
        self.assertTrue((self.root / dns_reset.JOURNAL).exists())
        self.recover()
        self.assertIsNone(self.recover())

    def test_modified_quarantine_and_malformed_journal_require_review_not_deletion(self):
        with patch("inventory.services._reset_dns_tracking", side_effect=OperationalError("DB failure")):
            with self.assertRaises(OperationalError):
                self.execute()
        journal = self.root / dns_reset.JOURNAL
        record = json.loads(journal.read_text())
        original_record = json.dumps(record)
        record["after"] = "0" * 64
        journal.write_text(json.dumps(record))
        with self.assertRaisesMessage(ValidationError, "fingerprint"):
            self.recover()
        journal.write_text(original_record)
        pin = self.root / record["quarantine"] / "generations" / self.old_generation / ".pin"
        pin.write_text("tampered")
        with self.assertRaisesMessage(ValidationError, "changed"):
            self.recover()
        journal.write_text("{}")
        with self.assertRaisesMessage(ValidationError, "Malformed"):
            self.recover()
        self.assertTrue(journal.exists())

    def test_uint32_timestamp_bounds_and_clock_rollback(self):
        for serial in (0, -1, True, MAX_SERIAL + 1):
            with self.assertRaises(ValidationError):
                dns_reset.preview(serial)
        with patch("inventory.dns_reset.initial_serial", return_value=MAX_SERIAL):
            plan, _ = dns_reset.preview()
            self.assertEqual(plan["timestamp"], MAX_SERIAL)
        with patch("inventory.dns_reset.initial_serial", return_value=self.timestamp - 1):
            with self.assertRaises(ValidationError):
                dns_reset.preview(self.timestamp)


class DNSResetConcurrencyTests(TransactionTestCase):
    def test_reset_excludes_local_publication_and_delivery_during_moves(self):
        Configuration.load()
        for index in range(1, 5):
            Site.objects.update_or_create(pk=index, defaults={"name": f"Site{index}", "g": index})
        with tempfile.TemporaryDirectory() as directory:
            Configuration.objects.update(dns_export_directory=directory, soa_serial=2026101004)
            publish_dns_zones("1")
            entered, release = Event(), Event()
            original = dns_reset._finish

            def pause(root, record):
                entered.set()
                if not release.wait(timeout=10):
                    raise RuntimeError("Test reset synchronization timed out.")
                return original(root, record)

            def execute():
                close_old_connections()
                try:
                    return dns_reset.reset(plan["timestamp"], token, confirmed=True,
                                           unloaded=True, nas_handled=True)
                finally:
                    close_old_connections()

            with patch("inventory.dns_reset.initial_serial", return_value=1791686400):
                plan, token = dns_reset.preview()
                with patch("inventory.dns_reset._finish", side_effect=pause):
                    with ThreadPoolExecutor(max_workers=1) as pool:
                        future = pool.submit(execute)
                        try:
                            self.assertTrue(entered.wait(timeout=10))
                            with self.assertRaises((ValidationError, OperationalError)):
                                publish_dns_zones("1")
                            with self.assertRaises((ValidationError, OperationalError)):
                                retry_delivery(1, "dnsgrid-2026101004")
                        finally:
                            release.set()
                        self.assertTrue(future.result(timeout=10).is_dir())
            self.assertEqual(Configuration.load().soa_serial, 1791686400)
            self.assertEqual(Configuration.load().revision, 1)
