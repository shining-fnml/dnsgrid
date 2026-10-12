import copy
import tempfile
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from unittest.mock import patch

from django.core.exceptions import ValidationError
from django.db import OperationalError, close_old_connections
from django.test import TestCase, TransactionTestCase

from .archives import restore, snapshot, validate
from .dns_serial import compare_serial, content_fingerprint, initial_serial, next_serial, validate_serial
from .exporters import build_exports
from .models import MAX_SERIAL, Configuration, Host, Site
from .services import delete_host, lower_dns_serial, move_host, save_host, update_settings


class DNSSerialTests(TestCase):
    def setUp(self):
        self.clock = patch("inventory.dns_serial.initial_serial", return_value=2026100800)
        self.clock.start()
        self.addCleanup(self.clock.stop)
        Configuration.objects.update(soa_serial=2026100800, dns_content_hash="")
        self.sites = list(Site.objects.values("id", "name", "g", "dsm_ifname"))

    def test_unix_seconds_and_monotonic_rules(self):
        with patch("inventory.dns_serial.datetime") as clock:
            instant = datetime(2026, 10, 8, 0, 0, 0, 999999, tzinfo=timezone.utc)
            clock.now.return_value = instant
            # Test the original function, not the patched initial_serial.
            self.assertEqual(initial_serial(), int(instant.timestamp()))
            clock.now.assert_called_with(timezone.utc)
        for previous, expected in ((2026100709, 2026100800), (2026100800, 2026100801),
                                   (2026100903, 2026100904), (20261008098, None)):
            with self.subTest(previous=previous):
                if expected is None:
                    with self.assertRaises(ValidationError):
                        next_serial(previous)
                else:
                    self.assertEqual(next_serial(previous), expected)
        for previous in (2026100899, 2026100999):
            self.assertEqual(next_serial(previous), previous + 1)
        for invalid in (True, -1, 1.5, "1692746706", MAX_SERIAL + 1):
            with self.assertRaises(ValidationError):
                validate_serial(invalid)
        for valid in (0, 42, 1692746706, 2026023000, MAX_SERIAL):
            validate_serial(valid)
        with patch("inventory.dns_serial.initial_serial", return_value=1692746706):
            self.assertEqual(next_serial(1692746706), 1692746707)
            self.assertEqual(next_serial(1692746708), 1692746709)
            self.assertEqual(next_serial(1692746700), 1692746706)
        with patch("inventory.dns_serial.initial_serial", return_value=MAX_SERIAL):
            self.assertEqual(next_serial(MAX_SERIAL - 1), MAX_SERIAL)
            with self.assertRaisesMessage(ValidationError, "exhausted"):
                next_serial(MAX_SERIAL)

    def test_rfc1982_wrap_and_ambiguity(self):
        for candidate, previous, expected in (
            (0, MAX_SERIAL, 1), (MAX_SERIAL, 0, -1), (42, 42, 0),
            (1692746707, 1692746706, 1), (1692746706, 1692746707, -1),
        ):
            self.assertEqual(compare_serial(candidate, previous), expected)
        for candidate, previous in ((0, 2**31), (2**31, 0), (MAX_SERIAL, 2**31 - 1)):
            with self.assertRaisesMessage(ValidationError, "Ambiguous RFC 1982"):
                compare_serial(candidate, previous)

    def test_baseline_lowering_rejects_active_delivery_before_changing_state(self):
        from .dns_delivery import _lock
        with tempfile.TemporaryDirectory() as directory:
            Configuration.objects.update(dns_export_directory=directory)
            before = snapshot()
            with _lock(directory), self.assertRaisesMessage(ValidationError, "Another DNS delivery"):
                lower_dns_serial(1, 2026100800, 1692746706, confirmed=True)
            self.assertEqual(snapshot(), before)
            with patch("inventory.services.initial_serial", return_value=1692746706):
                config = lower_dns_serial(1, 2026100800, 1692746706, confirmed=True)
            self.assertEqual(config.soa_serial, 1692746706)

    def test_content_mutations_but_not_metadata_or_gets_advance(self):
        host = Host(name="alpha", site_id=1, row=1, column=0)
        save_host(host, 1)
        self.assertEqual(Configuration.load().soa_serial, 2026100801)
        before = snapshot()
        self.assertEqual(build_exports(), build_exports())
        self.assertEqual(snapshot(), before)
        host.notes = "metadata"
        host.vpn = True
        save_host(host, Configuration.load().revision)
        self.assertEqual(Configuration.load().soa_serial, 2026100802)
        host.public_export = True
        save_host(host, Configuration.load().revision)
        self.assertEqual(Configuration.load().soa_serial, 2026100802)
        move_host(host.pk, "down", Configuration.load().revision)
        self.assertEqual(Configuration.load().soa_serial, 2026100803)
        update_settings({"ttl": 600}, self.sites, Configuration.load().revision)
        self.assertEqual(Configuration.load().soa_serial, 2026100804)
        delete_host(host.pk, Configuration.load().revision)
        self.assertEqual(Configuration.load().soa_serial, 2026100805)

    def test_exhaustion_rolls_back_inventory_and_revision(self):
        Configuration.objects.update(soa_serial=MAX_SERIAL)
        with self.assertRaises(ValidationError):
            save_host(Host(name="alpha", site_id=1, row=1, column=0), 1)
        self.assertFalse(Host.objects.exists())
        self.assertEqual(Configuration.load().revision, 1)

    def test_vpn_reverse_content_tracks_prefix_even_without_vpn_hosts(self):
        config = update_settings({"ttl": 600}, self.sites, 1)
        before = build_exports()
        fingerprint = config.dns_content_hash
        updated = update_settings({"vpn_prefix": "10.29"}, self.sites, config.revision)
        after = build_exports()
        self.assertEqual(updated.soa_serial, config.soa_serial + 1)
        self.assertNotEqual(updated.dns_content_hash, fingerprint)
        self.assertEqual(updated.dns_content_hash, content_fingerprint(updated))
        self.assertIn("$ORIGIN 29.10.in-addr.arpa.", after["reverse-vpn.zone"])
        for name in ("forward.zone", "vpn.zone", *(f"reverse-{g}.zone" for g in range(1, 5))):
            self.assertEqual(
                before[name].replace(f"        {config.soa_serial}\n", "        0\n"),
                after[name].replace(f"        {updated.soa_serial}\n", "        0\n"),
            )
        self.assertEqual(build_exports(), after)
        self.assertEqual(Configuration.load().soa_serial, updated.soa_serial)

    def test_upward_seed_is_distinct_and_stale_writer_cannot_claim_it(self):
        updated = update_settings({"soa_serial": 2026100902, "ttl": 600}, self.sites, 1)
        self.assertEqual((updated.revision, updated.soa_serial), (2, 2026100902))
        with self.assertRaises(ValidationError):
            save_host(Host(name="stale", site_id=1, row=1, column=0), 1)
        with self.assertRaises(ValidationError):
            update_settings({"soa_serial": 2026100901}, self.sites, 2)
        save_host(Host(name="alpha", site_id=1, row=1, column=0), 2)
        self.assertEqual(Configuration.load().soa_serial, 2026100903)

    def test_archive_never_lowers_serial_and_accepts_uint32_legacy(self):
        data = snapshot()
        update_settings({"soa_serial": 2026100902}, self.sites, 1)
        restore(data, 2)
        self.assertEqual(Configuration.load().soa_serial, 2026100902)
        legacy = copy.deepcopy(data)
        legacy["configuration"].pop("soa_serial")
        legacy["configuration"]["revision"] = 2026101002
        self.assertEqual(validate(legacy)["configuration"]["soa_serial"], 2026101002)
        legacy["configuration"]["revision"] = MAX_SERIAL
        self.assertEqual(validate(legacy)["configuration"]["soa_serial"], MAX_SERIAL)

    def test_archive_rfc1982_seed_and_ambiguous_restore_is_atomic(self):
        data = snapshot()
        Configuration.objects.update(soa_serial=MAX_SERIAL)
        data["configuration"]["soa_serial"] = 0
        restore(data, 1)
        self.assertEqual(Configuration.load().soa_serial, 0)
        before = snapshot()
        data["configuration"]["soa_serial"] = 2**31
        with self.assertRaisesMessage(ValidationError, "Ambiguous RFC 1982"):
            restore(data, Configuration.load().revision)
        self.assertEqual(snapshot(), before)

    def test_data_migration_preserves_higher_legacy_values(self):
        from importlib import import_module
        from django.apps import apps
        from types import SimpleNamespace
        migration = import_module("inventory.migrations.0007_configuration_dns_content_hash_and_more")
        for revision, expected in ((1, 2026100800), (2026101002, 2026101002), (MAX_SERIAL, MAX_SERIAL)):
            Configuration.objects.update(revision=revision)
            migration.preserve_serial(apps, SimpleNamespace(connection=SimpleNamespace(alias="default")))
            self.assertEqual(Configuration.load().soa_serial, expected)


class DNSConcurrentMutationTests(TransactionTestCase):
    def test_simultaneous_writers_cannot_assign_same_serial_to_different_content(self):
        Configuration.load()
        for index in range(1, 5):
            Site.objects.update_or_create(pk=index, defaults={"name": f"Site{index}", "g": index})
        Configuration.objects.update(soa_serial=2026100800)
        barrier = Barrier(2)

        def write(index):
            close_old_connections()
            try:
                barrier.wait(timeout=10)
                save_host(Host(name=f"host-{index}", site_id=1, row=index, column=0), 1)
                return "saved"
            except (ValidationError, OperationalError):
                return "rejected"
            finally:
                close_old_connections()

        with patch("inventory.dns_serial.initial_serial", return_value=2026100800):
            with ThreadPoolExecutor(max_workers=2) as pool:
                outcomes = list(pool.map(write, (1, 2)))
        self.assertCountEqual(outcomes, ["saved", "rejected"])
        self.assertEqual(Host.objects.count(), 1)
        self.assertEqual(Configuration.load().revision, 2)
        self.assertEqual(Configuration.load().soa_serial, 2026100801)
