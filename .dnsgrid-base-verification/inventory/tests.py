from unittest.mock import patch

from django.core.exceptions import ValidationError
from django.db import IntegrityError, transaction
from django.db.models.deletion import ProtectedError
from django.test import TestCase

from .models import MAX_SERIAL, Configuration, GandiRecord, Host, Site, normalize_mac
from .services import (
    delete_host, move_host, plan_placement, preview_host_move, save_host, update_settings,
)


class InventoryTestCase(TestCase):
    def setUp(self):
        self.config = Configuration.load()
        self.site = Site.objects.get(pk=1)

    def host(self, name="host", row=1, column=0, **kwargs):
        return Host(name=name, row=row, column=column, site=self.site, **kwargs)

    def insert(self, name="host", row=1, column=0, **kwargs):
        host = self.host(name, row, column, **kwargs)
        save_host(host, Configuration.load().revision)
        return host

    def site_data(self):
        return list(Site.objects.values("id", "name", "g"))

    def snapshot(self):
        return (
            Configuration.load().revision,
            list(Host.objects.values()),
            list(Site.objects.values()),
        )


class ModelTests(InventoryTestCase):
    def test_seed_and_singleton_defaults(self):
        self.assertEqual(self.config.pk, 1)
        self.assertEqual(self.config.revision, 1)
        from .dns_serial import initial_serial
        self.assertEqual(self.config.soa_serial, initial_serial())
        self.assertEqual(self.config.soa_ns, "ns.example.tld")
        self.assertEqual(
            list(Site.objects.values_list("id", "name", "g")),
            [(1, "Site1", 1), (2, "Site2", 2), (3, "Site3", 3), (4, "Site4", 4)],
        )
        self.assertEqual(Configuration.load().pk, self.config.pk)
        self.config.gandi_token = "do-not-display-this-value"
        self.assertNotIn(self.config.gandi_token, str(self.config))
        self.assertNotIn(self.config.gandi_token, repr(self.config))
        with self.assertRaises(IntegrityError), transaction.atomic():
            Configuration.objects.create(pk=2)

    def test_address_mapping_and_normalization(self):
        host = self.host(name="Server-01", row=15, column=7)
        host.full_clean()
        self.assertEqual(host.name, "server-01")
        self.assertEqual(host.x, 127)
        self.assertEqual(host.lan_address(self.config), "192.168.1.127")
        self.assertEqual(host.vpn_address(self.config), "172.28.1.127")
        self.assertEqual(host.lan_fqdn(self.config), "server-01.intranet.example.tld")
        self.assertEqual(host.vpn_fqdn(self.config), "server-01.vpn.example.tld")

    def test_all_127_usable_positions(self):
        for column in range(8):
            for row in range(16):
                if row == column == 0:
                    continue
                host = self.host(name=f"host-{column}-{row}", row=row, column=column)
                host.full_clean()
                host.save()
        self.assertEqual(Host.objects.count(), 127)
        self.assertEqual({host.x for host in Host.objects.all()}, set(range(1, 128)))

    def test_host_name_validation(self):
        for name in ("-bad", "bad-", "a.b", "bad name", "bad\nlabel", "bad;command", "a" * 64):
            with self.subTest(name=name), self.assertRaises(ValidationError):
                self.host(name=name).full_clean()
        self.insert(name="SERVER")
        with self.assertRaises(ValidationError):
            self.host(name="server", row=2).full_clean()

    def test_domain_and_prefix_validation(self):
        self.config.lan_domain = "INTRANET.Example.TLD."
        self.config.vpn_domain = "VPN.Example.TLD."
        self.config.lan_prefix = "001.002"
        self.config.full_clean()
        self.assertEqual(self.config.lan_domain, "intranet.example.tld")
        self.assertEqual(self.config.vpn_domain, "vpn.example.tld")
        self.assertEqual(self.config.lan_prefix, "1.2")
        for field, values in {
            "lan_domain": ("localhost", "a..example", "a.example\nIN A 1.2.3.4", "_a.example", "-a.example"),
            "vpn_domain": ("vpn.notexample.tld", "vpn.evil-example.tld"),
            "gandi_zone": ("com", "example.tld;rm"),
            "soa_ns": ("a.example\n$INCLUDE evil",),
            "soa_mailbox": ("hostmaster@example.tld",),
            "lan_prefix": ("1", "1.2.3", "-1.2", "256.2", "1.2\nA", "a.2", "１.2"),
        }.items():
            for value in values:
                candidate = Configuration.load()
                setattr(candidate, field, value)
                with self.subTest(field=field, value=value), self.assertRaises(ValidationError):
                    candidate.full_clean()

    def test_host_fqdn_length_limit(self):
        # 189 domain characters leave exactly 63 characters plus the separating dot.
        domain = ".".join(["a" * 63, "b" * 63, "c" * 61])
        Configuration.objects.filter(pk=1).update(
            lan_domain=domain, vpn_domain=domain, gandi_zone=domain
        )
        self.insert(name="h" * 63)
        too_long = domain + "d"
        Configuration.objects.filter(pk=1).update(
            lan_domain=too_long, vpn_domain=too_long, gandi_zone=too_long
        )
        with self.assertRaises(ValidationError):
            self.host(name="j" * 63, row=2).full_clean()

    def test_mac_normalization_and_uniqueness(self):
        for raw in ("02:AB:CD:EF:01:23", "02-ab-cd-ef-01-23", "02ab.cdef.0123", "02abcdef0123",
                    " 02:AB:CD:EF:01:23; ", "\t02-ab-cd-ef-01-23 ;\n",
                    "02ab.cdef.0123;", "02abcdef0123;"):
            with self.subTest(raw=raw):
                self.assertEqual(normalize_mac(raw), "02:ab:cd:ef:01:23")
        for raw in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff", "01:00:5e:01:02:03",
                    "02:zz:00:00:00:00", "02-ab:cd-ef:01-23", "02abc", "02abcdef0123\nbad",
                    ";", " ; ", "02abcdef0123;;", "02abcdef0123; ;", "02ab; cdef0123",
                    "00:00:00:00:00:00;", "ff:ff:ff:ff:ff:ff;", "01:00:5e:01:02:03;"):
            with self.subTest(raw=raw), self.assertRaises(ValidationError):
                normalize_mac(raw)
        host = self.insert(name="one", mac=" 02:AB:CD:EF:01:23 ; ")
        host.refresh_from_db()
        self.assertEqual(host.mac, "02:ab:cd:ef:01:23")
        with self.assertRaises(ValidationError):
            self.insert(name="two", row=2, mac="02-ab-cd-ef-01-23;")
        self.insert(name="empty-one", row=3)
        self.insert(name="empty-two", row=4)
        self.assertEqual(Host.objects.filter(mac="").count(), 2)
        with self.assertRaises(IntegrityError), transaction.atomic():
            Host.objects.create(name="duplicate-mac", site=self.site, row=5, column=0,
                                mac="02:ab:cd:ef:01:23")

    def test_model_choices_lengths_and_db_bounds(self):
        for kwargs in (
            {"row": 0, "column": 0}, {"row": 16}, {"row": -1},
            {"column": 8}, {"column": -1}, {"status": "unknown"},
            {"category": "a" * 81}, {"notes": "a" * 4001},
        ):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValidationError):
                self.host(**kwargs).full_clean()
        for kwargs in (
            {"row": 0, "column": 0}, {"row": 16}, {"column": 8}, {"status": "unknown"},
        ):
            with self.subTest(kwargs=kwargs), self.assertRaises(IntegrityError), transaction.atomic():
                self.host(**kwargs).save()
        for field in ("ttl", "revision"):
            for value in (0, MAX_SERIAL + 1):
                with self.subTest(field=field, value=value), self.assertRaises(ValidationError):
                    candidate = Configuration.load()
                    setattr(candidate, field, value)
                    candidate.full_clean()
                with self.assertRaises(IntegrityError), transaction.atomic():
                    Configuration.objects.filter(pk=1).update(**{field: value})
        for kwargs in ({"id": 5, "g": 1}, {"id": 4, "g": 256}):
            with self.assertRaises(IntegrityError), transaction.atomic():
                Site.objects.update_or_create(pk=kwargs["id"], defaults={"name": "Bad", "g": kwargs["g"]})

    def test_site_is_protected(self):
        self.insert()
        with self.assertRaises(ProtectedError):
            self.site.delete()

    def test_ownership_ledger_constraints(self):
        record = GandiRecord(zone="EXAMPLE.TLD.", name="SERVER.VPN", values=["172.28.1.1"])
        record.full_clean()
        record.save()
        self.assertEqual(record.zone, "example.tld")
        self.assertEqual(record.name, "server.vpn")
        with self.assertRaises(IntegrityError), transaction.atomic():
            GandiRecord.objects.create(zone=record.zone, name=record.name, values=["172.28.2.1"])
        with self.assertRaises(IntegrityError), transaction.atomic():
            GandiRecord.objects.create(zone=record.zone, name="other", record_type="X")
        record.values = {"bad": "not-a-list"}
        with self.assertRaises(ValidationError):
            record.full_clean()


class PlacementTests(InventoryTestCase):
    def test_preview_and_insert_shift_descending_only_until_gap(self):
        one = self.insert(name="one", row=1)
        two = self.insert(name="two", row=2)
        four = self.insert(name="four", row=4)
        other = self.insert(name="other", row=1, column=1)
        before = self.snapshot()
        self.assertEqual(plan_placement(1, 0), [
            {"id": one.pk, "name": "one", "from_row": 1, "to_row": 2},
            {"id": two.pk, "name": "two", "from_row": 2, "to_row": 3},
        ])
        self.assertEqual(self.snapshot(), before)
        self.insert(name="new", row=1)
        one.refresh_from_db()
        two.refresh_from_db()
        four.refresh_from_db()
        other.refresh_from_db()
        self.assertEqual((one.row, two.row, four.row, other.row), (2, 3, 4, 1))
        self.assertEqual(other.column, 1)

    def test_full_column_rejected_atomically_and_never_crosses_boundary(self):
        for row in range(1, 16):
            self.insert(name=f"full-{row}", row=row)
        before = self.snapshot()
        with self.assertRaises(ValidationError):
            self.insert(name="overflow", row=1)
        self.assertEqual(before, self.snapshot())
        with self.assertRaises(ValidationError):
            plan_placement(15, 0)
        self.assertFalse(Host.objects.filter(column=1).exists())

    def test_lower_boundary_without_room_does_not_fill_holes_above(self):
        self.insert(name="last", row=15, column=7)
        before = self.snapshot()
        with self.assertRaises(ValidationError):
            self.insert(name="blocked", row=15, column=7)
        self.assertEqual(before, self.snapshot())
        self.assertEqual(plan_placement(14, 7), [])

    def test_reserved_and_out_of_range_rejected(self):
        for row, column in ((0, 0), (-1, 0), (16, 0), (1, 8), (1, -1), ("1", 0)):
            with self.subTest(row=row, column=column), self.assertRaises(ValidationError):
                plan_placement(row, column)
        before = self.snapshot()
        with self.assertRaises(ValidationError):
            self.insert(row=0, column=0)
        self.assertEqual(before, self.snapshot())

    def test_move_within_column_frees_old_cell_for_shift(self):
        upper = self.insert(name="upper", row=1)
        middle = self.insert(name="middle", row=2)
        moving = self.insert(name="moving", row=3)
        identity = moving.pk
        moving.row = 1
        save_host(moving, Configuration.load().revision)
        moving.refresh_from_db()
        upper.refresh_from_db()
        middle.refresh_from_db()
        self.assertEqual(moving.pk, identity)
        self.assertEqual((moving.row, upper.row, middle.row), (1, 2, 3))
        self.assertEqual(Host.objects.count(), 3)

    def test_move_to_another_column_does_not_compact_old_column(self):
        moving = self.insert(name="moving", row=1)
        lower = self.insert(name="lower", row=2)
        target = self.insert(name="target", row=1, column=1)
        moving.column = 1
        save_host(moving, Configuration.load().revision)
        lower.refresh_from_db()
        target.refresh_from_db()
        self.assertEqual(lower.row, 2)
        self.assertEqual(target.row, 2)
        self.assertFalse(Host.objects.filter(row=1, column=0).exists())

    def test_same_position_and_site_change_preserve_x(self):
        host = self.insert(row=2, column=3)
        revision = Configuration.load().revision
        self.assertEqual(plan_placement(2, 3, exclude_host_id=host.pk), [])
        save_host(host, revision)
        self.assertEqual(Configuration.load().revision, revision)
        host.site = Site.objects.get(pk=4)
        save_host(host, revision)
        host.refresh_from_db()
        self.assertEqual(host.x, 50)
        self.assertEqual(host.lan_address(Configuration.load()), "192.168.4.50")
        self.assertEqual(Configuration.load().revision, revision + 1)

    def test_delete_leaves_hole_and_stale_delete_is_rejected(self):
        upper = self.insert(name="upper", row=1)
        lower = self.insert(name="lower", row=2)
        revision = Configuration.load().revision
        delete_host(upper.pk, revision)
        lower.refresh_from_db()
        self.assertEqual(lower.row, 2)
        self.assertFalse(Host.objects.filter(row=1, column=0).exists())
        before = self.snapshot()
        with self.assertRaises(ValidationError):
            delete_host(lower.pk, revision)
        self.assertEqual(before, self.snapshot())

    def test_stale_save_and_invalid_save_never_mutate_inventory(self):
        revision = Configuration.load().revision
        host = self.insert()
        before = self.snapshot()
        with self.assertRaises(ValidationError):
            save_host(self.host(name="stale", row=2), revision)
        with self.assertRaises(ValidationError):
            save_host(host, revision)
        with self.assertRaises(ValidationError):
            self.insert(name="bad name", row=1)
        with self.assertRaises(ValidationError):
            delete_host(99999, Configuration.load().revision)
        self.assertEqual(before, self.snapshot())

    def test_invalid_shifted_insert_rolls_back(self):
        self.insert(name="one", row=1)
        self.insert(name="two", row=2)
        before = self.snapshot()
        with self.assertRaises(ValidationError):
            self.insert(name="one", row=1)
        self.assertEqual(before, self.snapshot())

    def test_database_error_after_shifts_rolls_back_revision_and_positions(self):
        self.insert(name="one", row=1)
        self.insert(name="two", row=2)
        before = self.snapshot()
        with patch.object(Host, "save", side_effect=IntegrityError("simulated save failure")):
            with self.assertRaises(ValidationError):
                self.insert(name="new", row=1)
        self.assertEqual(before, self.snapshot())

    def test_database_error_after_moving_delete_restores_original_host(self):
        moving = self.insert(name="moving", row=3)
        self.insert(name="one", row=1)
        before = self.snapshot()
        moving.row = 1
        with patch.object(Host, "save", side_effect=IntegrityError("simulated move failure")):
            with self.assertRaises(ValidationError):
                save_host(moving, Configuration.load().revision)
        self.assertEqual(before, self.snapshot())

    def test_uint32_serial_limit(self):
        Configuration.objects.filter(pk=1).update(revision=MAX_SERIAL)
        before = self.snapshot()
        with self.assertRaises(ValidationError):
            save_host(self.host(), MAX_SERIAL)
        self.assertEqual(before, self.snapshot())


class QuickMoveTests(InventoryTestCase):
    def test_adjacent_moves_preserve_identity_metadata_and_other_hosts(self):
        for start, direction, target in (
            (2, "up", 1), (2, "down", 3), (16, "up", 15), (15, "down", 16),
        ):
            with self.subTest(start=start, direction=direction):
                host = self.insert(
                    row=start % 16, column=start // 16, category="Hardware",
                    status=Host.Status.DECOMMISSIONED, vpn=True, public_export=True,
                    mac="02:00:00:00:00:01", notes="Keep these notes",
                )
                host.site_id = 4
                save_host(host, Configuration.load().revision)
                other = self.insert(name="other", row=14, column=7)
                before = Host.objects.values().get(pk=host.pk)
                other_before = Host.objects.values().get(pk=other.pk)
                snapshot = self.snapshot()
                revision = Configuration.load().revision
                old, candidate, config = preview_host_move(host.pk, direction, revision)
                self.assertEqual((old.x, candidate.x, config.revision), (start, target, revision))
                self.assertEqual(self.snapshot(), snapshot)
                moved = move_host(host.pk, direction, revision)
                self.assertEqual(moved.pk, host.pk)
                before.update(row=target % 16, column=target // 16)
                self.assertEqual(Host.objects.values().get(pk=host.pk), before)
                self.assertEqual(Host.objects.values().get(pk=other.pk), other_before)
                self.assertFalse(Host.objects.filter(row=start % 16, column=start // 16).exists())
                self.assertEqual(Configuration.load().revision, revision + 1)
                Host.objects.all().delete()

    def test_invalid_direction_bounds_occupancy_and_stale_revision_are_atomic(self):
        host = self.insert()
        self.insert(name="blocking", row=2)
        for service in (preview_host_move, move_host):
            for direction, revision in (
                ("up", Configuration.load().revision),
                ("down", Configuration.load().revision),
                ("sideways", Configuration.load().revision),
                (None, Configuration.load().revision),
                ("down", 1),
            ):
                with self.subTest(service=service.__name__, direction=direction, revision=revision):
                    before = self.snapshot()
                    with self.assertRaises(ValidationError):
                        service(host.pk, direction, revision)
                    self.assertEqual(self.snapshot(), before)
        Host.objects.filter(pk=host.pk).update(row=15, column=7)
        for service in (preview_host_move, move_host):
            before = self.snapshot()
            with self.assertRaises(ValidationError):
                service(host.pk, "down", Configuration.load().revision)
            self.assertEqual(self.snapshot(), before)

    def test_deleted_host_and_serial_limit_do_not_change_revision(self):
        host = self.insert()
        for service in (preview_host_move, move_host):
            before = self.snapshot()
            with self.assertRaisesMessage(ValidationError, "no longer exists"):
                service(host.pk + 1, "down", Configuration.load().revision)
            self.assertEqual(self.snapshot(), before)
        Configuration.objects.filter(pk=1).update(revision=MAX_SERIAL)
        before = self.snapshot()
        preview_host_move(host.pk, "down", MAX_SERIAL)
        with self.assertRaisesMessage(ValidationError, "maximum"):
            move_host(host.pk, "down", MAX_SERIAL)
        self.assertEqual(self.snapshot(), before)

    def test_database_error_rolls_back_position_and_revision(self):
        host = self.insert()
        before = self.snapshot()
        with patch.object(Host, "save", side_effect=IntegrityError("conflict")):
            with self.assertRaises(ValidationError):
                move_host(host.pk, "down", Configuration.load().revision)
        self.assertEqual(self.snapshot(), before)

    def test_revision_is_claimed_before_loading_host_or_destination(self):
        from django.db import connection
        from django.test.utils import CaptureQueriesContext
        host = self.insert()
        for service in (preview_host_move, move_host):
            with CaptureQueriesContext(connection) as queries:
                service(host.pk, "down", Configuration.load().revision)
            sql = [query["sql"] for query in queries]
            claim = next(index for index, query in enumerate(sql) if query.startswith("UPDATE"))
            host_read = next(index for index, query in enumerate(sql) if (
                query.startswith("SELECT") and 'FROM "inventory_host"' in query
            ))
            self.assertIn('"inventory_configuration"', sql[claim])
            self.assertLess(claim, host_read)


class SettingsTests(InventoryTestCase):
    def test_domain_update_rejects_overlong_existing_host_fqdns(self):
        self.insert(name="h" * 63)
        domain = ".".join(["a" * 63, "b" * 63, "c" * 62])
        before = self.snapshot()
        with self.assertRaises(ValidationError):
            update_settings(
                {"lan_domain": domain, "vpn_domain": domain, "gandi_zone": domain},
                self.site_data(), Configuration.load().revision,
            )
        self.assertEqual(before, self.snapshot())

    def test_site_octet_and_name_swap_and_global_configuration(self):
        host = self.insert(row=15, column=7)
        sites = self.site_data()
        sites[0]["g"], sites[1]["g"] = sites[1]["g"], sites[0]["g"]
        sites[0]["name"], sites[1]["name"] = sites[1]["name"], sites[0]["name"]
        revision = Configuration.load().revision
        config = update_settings({"lan_prefix": "10.44", "ttl": 600}, sites, revision)
        self.assertEqual(config.revision, revision + 1)
        self.assertEqual(Configuration.load().ttl, 600)
        host.refresh_from_db()
        self.assertEqual(host.x, 127)
        self.assertEqual(host.lan_address(config), "10.44.2.127")
        self.assertEqual(Site.objects.get(pk=1).name, "Site2")

    def test_noop_and_normalized_settings_do_not_bump_revision(self):
        revision = Configuration.load().revision
        returned = update_settings({"lan_domain": "INTRANET.EXAMPLE.TLD."}, self.site_data(), revision)
        self.assertEqual(returned.revision, revision)
        self.assertEqual(Configuration.load().revision, revision)

    def test_invalid_sites_are_rejected_atomically(self):
        before = self.snapshot()
        for change in ("missing", "extra", "duplicate-id", "duplicate-g", "duplicate-name", "out-of-range"):
            sites = self.site_data()
            if change == "missing":
                sites.pop()
            elif change == "extra":
                sites.append({"id": 5, "name": "Site5", "g": 5})
            elif change == "duplicate-id":
                sites[1]["id"] = 1
            elif change == "duplicate-g":
                sites[1]["g"] = sites[0]["g"]
            elif change == "duplicate-name":
                sites[1]["name"] = sites[0]["name"].upper()
            else:
                sites[1]["g"] = 256
            with self.subTest(change=change), self.assertRaises(ValidationError):
                update_settings({"ttl": 600}, sites, Configuration.load().revision)
            self.assertEqual(before, self.snapshot())

    def test_invalid_configuration_and_stale_settings_leave_no_changes(self):
        before = self.snapshot()
        with self.assertRaises(ValidationError):
            update_settings({"vpn_domain": "vpn.invalid.tld"}, self.site_data(), self.config.revision)
        with self.assertRaises(ValidationError):
            update_settings({"revision": 100}, self.site_data(), self.config.revision)
        self.assertEqual(before, self.snapshot())
        update_settings({"ttl": 600}, self.site_data(), self.config.revision)
        before = self.snapshot()
        with self.assertRaises(ValidationError):
            update_settings({"ttl": 900}, self.site_data(), self.config.revision)
        self.assertEqual(before, self.snapshot())

    def test_malformed_settings_input_is_validation_error(self):
        for configuration, sites in ((None, []), ({}, None), ({}, [None] * 4)):
            with self.subTest(configuration=configuration, sites=sites), self.assertRaises(ValidationError):
                update_settings(configuration, sites, self.config.revision)
