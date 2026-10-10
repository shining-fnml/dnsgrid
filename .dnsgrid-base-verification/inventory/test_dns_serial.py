import copy
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from unittest.mock import patch

from django.core.exceptions import ValidationError
from django.db import OperationalError, close_old_connections
from django.test import TestCase, TransactionTestCase

from .archives import restore, snapshot, validate
from .dns_serial import initial_serial, next_serial, validate_serial
from .exporters import build_exports
from .models import MAX_SERIAL, Configuration, Host, Site
from .services import delete_host, move_host, save_host, update_settings


class DNSSerialTests(TestCase):
    def setUp(self):
        self.clock = patch("inventory.dns_serial.initial_serial", return_value=2026100800)
        self.clock.start()
        self.addCleanup(self.clock.stop)
        Configuration.objects.update(soa_serial=2026100800, dns_content_hash="")
        self.sites = list(Site.objects.values("id", "name", "g", "dsm_ifname"))

    def test_utc_day_and_calendar_counter_rules(self):
        with patch("inventory.dns_serial.datetime") as clock:
            clock.now.return_value = datetime(2026, 10, 8, 0, 0, tzinfo=timezone.utc)
            # Test the original function, not the patched initial_serial.
            self.assertEqual(initial_serial(), 2026100800)
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
            with self.assertRaisesMessage(ValidationError, "exhausted"):
                next_serial(previous)
        for invalid in (True, 42, 2026023000, 2026130100, MAX_SERIAL, MAX_SERIAL + 1):
            with self.assertRaises(ValidationError):
                validate_serial(invalid)
        validate_serial(4294123199)

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
        self.assertEqual(Configuration.load().soa_serial, 2026100801)
        move_host(host.pk, "down", Configuration.load().revision)
        self.assertEqual(Configuration.load().soa_serial, 2026100802)
        update_settings({"ttl": 600}, self.sites, Configuration.load().revision)
        self.assertEqual(Configuration.load().soa_serial, 2026100803)
        delete_host(host.pk, Configuration.load().revision)
        self.assertEqual(Configuration.load().soa_serial, 2026100804)

    def test_exhaustion_rolls_back_inventory_and_revision(self):
        Configuration.objects.update(soa_serial=2026100899)
        with self.assertRaises(ValidationError):
            save_host(Host(name="alpha", site_id=1, row=1, column=0), 1)
        self.assertFalse(Host.objects.exists())
        self.assertEqual(Configuration.load().revision, 1)

    def test_upward_seed_is_distinct_and_stale_writer_cannot_claim_it(self):
        updated = update_settings({"soa_serial": 2026100902, "ttl": 600}, self.sites, 1)
        self.assertEqual((updated.revision, updated.soa_serial), (2, 2026100902))
        with self.assertRaises(ValidationError):
            save_host(Host(name="stale", site_id=1, row=1, column=0), 1)
        with self.assertRaises(ValidationError):
            update_settings({"soa_serial": 2026100901}, self.sites, 2)
        save_host(Host(name="alpha", site_id=1, row=1, column=0), 2)
        self.assertEqual(Configuration.load().soa_serial, 2026100903)

    def test_archive_never_lowers_serial_and_rejects_incompatible_legacy(self):
        data = snapshot()
        update_settings({"soa_serial": 2026100902}, self.sites, 1)
        restore(data, 2)
        self.assertEqual(Configuration.load().soa_serial, 2026100902)
        legacy = copy.deepcopy(data)
        legacy["configuration"].pop("soa_serial")
        legacy["configuration"]["revision"] = 2026101002
        self.assertEqual(validate(legacy)["configuration"]["soa_serial"], 2026101002)
        legacy["configuration"]["revision"] = MAX_SERIAL
        with self.assertRaisesMessage(ValidationError, "administrator-coordinated"):
            validate(legacy)

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
