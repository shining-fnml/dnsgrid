import copy
import json
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.core.files.uploadedfile import SimpleUploadedFile
from django.db import OperationalError, close_old_connections, connection
from django.db.migrations.executor import MigrationExecutor
from django.test import TestCase, TransactionTestCase
from django.urls import reverse

from .archives import dumps, fingerprint, restore, snapshot, validate
from .dsm import reservation_form_body, reservation_payload, reservation_request
from .exporters import build_exports
from .models import Configuration, Host, Site
from .services import (
    delete_host, move_host, plan_placement, preview_host_change, preview_host_move,
    revoke_host_static, save_host, update_settings,
)


class StaticHostTests(TestCase):
    def setUp(self):
        self.config = Configuration.load()
        self.host = Host.objects.create(
            name="fixed", site_id=1, row=2, column=0, static=True, vpn=True,
            public_export=True, mac="02:00:00:00:00:01",
        )

    def assert_rejected_unchanged(self, operation):
        before = snapshot()
        with self.assertRaises(ValidationError):
            operation()
        self.assertEqual(snapshot(), before)

    def test_existing_static_cannot_be_edited_or_unflagged_even_using_detached_objects(self):
        for field, value in (
            ("name", "renamed"), ("site_id", 2), ("row", 3), ("column", 1),
            ("category", "new"), ("notes", "new"), ("status", "decommissioned"),
            ("vpn", False), ("public_export", False), ("mac", ""), ("static", False),
        ):
            with self.subTest(field=field):
                candidate = copy.copy(self.host)
                setattr(candidate, field, value)
                self.assert_rejected_unchanged(lambda: save_host(candidate, 1))
                self.assert_rejected_unchanged(lambda: preview_host_change(candidate, 1))
        candidate = copy.copy(self.host)
        candidate.static, candidate.notes = False, "combined"
        self.assert_rejected_unchanged(lambda: save_host(candidate, 1))

    def test_noop_static_save_and_separate_revocation_preserve_dns_serial(self):
        before = build_exports()
        save_host(copy.copy(self.host), 1)
        self.assertEqual(Configuration.load().revision, 1)
        serial = Configuration.load().soa_serial
        revoke_host_static(self.host.pk, 1)
        self.assertFalse(Host.objects.get(pk=self.host.pk).static)
        self.assertEqual(Configuration.load().revision, 2)
        self.assertEqual(Configuration.load().soa_serial, serial)
        self.assertEqual(build_exports(), before)
        self.assert_rejected_unchanged(lambda: revoke_host_static(self.host.pk, 2))

    def test_enabling_static_advances_revision_but_not_dns_serial(self):
        Host.objects.filter(pk=self.host.pk).update(static=False)
        save_host(copy.copy(self.host), 1)
        self.assertTrue(Host.objects.get(pk=self.host.pk).static)
        self.assertEqual(Configuration.load().revision, 2)
        self.assertEqual(Configuration.load().soa_serial, self.config.soa_serial)

    def test_static_cannot_be_deleted_or_quick_moved_at_preview_or_apply(self):
        for operation in (
            lambda: delete_host(self.host.pk, 1),
            lambda: preview_host_move(self.host.pk, "up", 1),
            lambda: move_host(self.host.pk, "up", 1),
        ):
            self.assert_rejected_unchanged(operation)

    def test_contiguous_shift_blocked_atomically_but_host_below_gap_untouched(self):
        first = Host.objects.create(name="first", site_id=1, row=1, column=0)
        self.assert_rejected_unchanged(lambda: plan_placement(1, 0))
        self.assert_rejected_unchanged(
            lambda: save_host(Host(name="new", site_id=1, row=1, column=0), 1),
        )
        moving = Host.objects.create(name="moving", site_id=1, row=1, column=1)
        moving.column = 0
        self.assert_rejected_unchanged(lambda: save_host(moving, 1))
        first.delete()
        save_host(Host(name="new", site_id=1, row=1, column=0), 1)
        self.host.refresh_from_db()
        self.assertEqual(self.host.row, 2)

    def test_settings_block_only_effective_address_changes(self):
        sites = list(Site.objects.values("id", "name", "g", "dsm_ifname"))
        for field, value in (("lan_prefix", "10.20"), ("vpn_prefix", "10.30")):
            self.assert_rejected_unchanged(lambda: update_settings({field: value}, sites, 1))
        changed_sites = copy.deepcopy(sites)
        changed_sites[0]["g"] = 8
        self.assert_rejected_unchanged(lambda: update_settings({}, changed_sites, 1))
        changed_sites = copy.deepcopy(sites)
        changed_sites[1].update(g=8, name="Renamed", dsm_ifname="eth0")
        update_settings({"lan_domain": "lan.example.tld", "ttl": 600}, changed_sites, 1)
        self.assertEqual(Configuration.load().revision, 2)
        self.assertEqual(Host.objects.get(pk=self.host.pk).lan_address(Configuration.load()), "192.168.1.2")
        Host.objects.filter(pk=self.host.pk).update(vpn=False)
        update_settings({"vpn_prefix": "10.30"}, changed_sites, 2)

    def test_all_dsm_variants_exclude_static_even_with_mac_but_dns_and_gandi_include(self):
        site = Site.objects.get(pk=1)
        site.dsm_ifname = "eth0"
        site.save()
        other = Host.objects.create(
            name="leased", site=site, row=3, column=0, mac="02:00:00:00:00:02",
        )
        hosts = [self.host, other]
        payload = reservation_payload(self.config, site, hosts)
        self.assertEqual([item["hostname"] for item in payload["reservationData"]], ["leased"])
        request = reservation_request(self.config, site, hosts)
        self.assertNotIn("fixed", json.dumps(request))
        self.assertNotIn("fixed", reservation_form_body(self.config, site, hosts))
        outputs = build_exports()
        self.assertNotIn("fixed", outputs["dsm-reservations-site-1.json"])
        self.assertIn("fixed.intranet.example.tld.", outputs["forward.zone"])
        self.assertIn("PTR fixed.intranet.example.tld.", outputs["reverse-1.zone"])
        self.assertIn("fixed.vpn.", outputs["vpn.zone"])
        self.assertIn("PTR fixed.vpn.", outputs["reverse-vpn.zone"])
        self.assertIn("fixed.vpn", outputs["gandi.json"])

    def test_archive_v2_static_roundtrip_and_explicit_legacy_policy(self):
        data = snapshot()
        self.assertEqual(data["schema_version"], 2)
        self.assertTrue(validate(data)["hosts"][0]["static"])
        for value in (1, "true", None, [], {}):
            candidate = copy.deepcopy(data)
            candidate["hosts"][0]["static"] = value
            self.assert_rejected_unchanged(lambda: validate(candidate))
        candidate = copy.deepcopy(data)
        candidate["hosts"][0].pop("static")
        self.assert_rejected_unchanged(lambda: validate(candidate))
        legacy = copy.deepcopy(candidate)
        legacy["schema_version"] = 1
        normalized = validate(legacy)
        self.assertEqual(normalized["schema_version"], 2)
        self.assertFalse(normalized["hosts"][0]["static"])
        legacy["hosts"][0]["static"] = False
        self.assert_rejected_unchanged(lambda: validate(legacy))
        restore(data, 1, fingerprint(snapshot()))
        self.assertTrue(Host.objects.get(pk=self.host.pk).static)

    def test_v2_rejects_legacy_config_and_site_shapes_and_unknown_versions(self):
        for mutate in (
            lambda data: data["configuration"].pop("soa_serial"),
            lambda data: data["configuration"].update(dns_nas_host="retired"),
            lambda data: data["sites"][0].pop("dsm_ifname"),
            lambda data: data.update(schema_version=True),
            lambda data: data.update(schema_version=3),
            lambda data: data.update(schema_version="2"),
        ):
            candidate = snapshot()
            mutate(candidate)
            self.assert_rejected_unchanged(lambda: validate(candidate))


class StaticHostViewTests(TestCase):
    def setUp(self):
        self.config = Configuration.load()
        self.host = Host.objects.create(name="fixed", site_id=1, row=2, column=0, static=True)
        self.client.force_login(get_user_model().objects.create_user("operator", is_staff=True))

    def edit_data(self):
        return {
            "name": self.host.name, "site": 1, "row": 2, "column": 0,
            "status": "running", "static": "on", "revision": 1,
        }

    def confirm(self):
        return self.client.post(reverse("confirm"), {"nonce": self.client.session["pending"]["nonce"]})

    def test_grid_marker_and_readonly_details_preserve_other_styles(self):
        response = self.client.get(reverse("grid"))
        self.assertContains(response, 'class="occupied running site-1"')
        self.assertContains(response, 'aria-label="Static host: read-only, excluded from DHCP"')
        self.assertContains(response, "color: #b91c1c")
        response = self.client.get(reverse("host-edit", args=[self.host.pk]))
        self.assertContains(response, "192.168.1.2")
        self.assertContains(response, "disabled")
        self.assertContains(response, "Preview static protection revocation")
        for label in ("Preview deletion", "Move up", "Move down", "Insert a new host here", "Preview changes"):
            self.assertNotContains(response, label)

    def test_static_dot_composes_with_every_site_status_and_vpn_name_style(self):
        for site in Site.objects.all():
            for status in Host.Status.values:
                for vpn in (False, True):
                    Host.objects.filter(pk=self.host.pk).update(
                        site=site, status=status, vpn=vpn, public_export=True,
                    )
                    response = self.client.get(reverse("grid"))
                    self.assertContains(response, f'class="occupied {status} site-{site.pk}"')
                    expected = "host-name vpn-name" if vpn else "host-name"
                    self.assertContains(response, f'class="{expected}"')
                    name = "(fixed)" if status == "decommissioned" else "fixed"
                    self.assertContains(response, f">{name} <span")
                    self.assertContains(response, 'aria-label="Static host: read-only, excluded from DHCP"')
                    if vpn:
                        self.assertContains(response, 'class="vpn-address published-address"')

    def test_edit_unflag_and_combined_revocation_posts_are_rejected(self):
        for data in (self.edit_data(), {**self.edit_data(), "static": ""},
                     {**self.edit_data(), "action": "revoke-static"}):
            response = self.client.post(reverse("host-edit", args=[self.host.pk]), data)
            self.assertEqual(response.status_code, 200)
            self.assertNotIn("pending", self.client.session)
            self.assertTrue(Host.objects.get(pk=self.host.pk).static)
        self.client.post(reverse("host-delete", args=[self.host.pk]))
        self.assertNotIn("pending", self.client.session)

    def test_revocation_is_own_preview_confirm_operation_and_rechecks_revision(self):
        url = reverse("host-edit", args=[self.host.pk])
        data = {"action": "revoke-static", "revision": 1}
        self.client.post(url, data)
        self.assertTrue(Host.objects.get(pk=self.host.pk).static)
        Configuration.objects.update(revision=2)
        self.confirm()
        self.assertTrue(Host.objects.get(pk=self.host.pk).static)
        data["revision"] = 2
        self.client.post(url, data)
        self.confirm()
        self.assertFalse(Host.objects.get(pk=self.host.pk).static)
        self.assertEqual(Configuration.load().revision, 3)

    def test_pending_edit_move_delete_and_shift_recheck_new_static_state(self):
        Host.objects.filter(pk=self.host.pk).update(static=False)
        url = reverse("host-edit", args=[self.host.pk])
        data = self.edit_data()
        data.update(name="changed", static="")
        self.client.post(url, data)
        Host.objects.filter(pk=self.host.pk).update(static=True)
        self.confirm()
        self.assertEqual(Host.objects.get(pk=self.host.pk).name, "fixed")
        for route, post in (("host-move", {"direction": "up", "revision": 1}), ("host-delete", {})):
            Host.objects.filter(pk=self.host.pk).update(static=False)
            self.client.post(reverse(route, args=[self.host.pk]), post)
            Host.objects.filter(pk=self.host.pk).update(static=True)
            self.confirm()
            self.assertEqual(Host.objects.get(pk=self.host.pk).row, 2)
        Host.objects.filter(pk=self.host.pk).update(static=False)
        data.update(name="inserted", row=2)
        self.client.post(reverse("host-create"), data)
        Host.objects.filter(pk=self.host.pk).update(static=True)
        self.confirm()
        self.assertFalse(Host.objects.filter(name="inserted").exists())
        self.assertEqual(Configuration.load().revision, 1)

    def test_settings_preview_blocks_static_addresses_and_confirmation_rechecks_state(self):
        response = self.client.get(reverse("configuration"))
        self.assertContains(response, "Settings cannot change a static host's assigned LAN IP.")
        self.assertContains(response, "VPN addresses are protected only for VPN members.")
        self.assertContains(response, "Revoke static protection separately first.")
        self.assertContains(response, "unrelated settings remain editable.")
        form = response.context["form"]
        data = {
            name: form[name].value() for name in form.fields
            if name not in ("gandi_token", "clear_token")
        }
        data["gandi_token_expires_on"] = ""
        data["lan_prefix"] = "10.20"
        response = self.client.post(reverse("configuration"), data)
        self.assertContains(response, "static host fixed")
        self.assertNotIn("pending", self.client.session)
        Host.objects.filter(pk=self.host.pk).update(static=False)
        self.client.post(reverse("configuration"), data)
        self.assertIn("pending", self.client.session)
        Host.objects.filter(pk=self.host.pk).update(static=True)
        self.confirm()
        self.assertEqual(Configuration.load().lan_prefix, "192.168")
        self.assertEqual(Configuration.load().revision, 1)

    def test_toggle_checkbox_preview_and_confirm_preserves_dns_serial(self):
        Host.objects.filter(pk=self.host.pk).update(static=False)
        self.client.post(reverse("host-edit", args=[self.host.pk]), self.edit_data())
        self.assertFalse(Host.objects.get(pk=self.host.pk).static)
        self.confirm()
        self.assertTrue(Host.objects.get(pk=self.host.pk).static)
        self.assertEqual(Configuration.load().revision, 2)
        self.assertEqual(Configuration.load().soa_serial, self.config.soa_serial)

    def test_archive_static_replacement_requires_ack_and_preserves_incoming_flag(self):
        data = snapshot()
        data["hosts"][0].update(name="replacement", static=True)
        def preview():
            response = self.client.post(reverse("archive-upload"), {
                "revision": 1, "archive": SimpleUploadedFile("archive.json", dumps(data).encode()),
            })
            self.assertContains(response, "protected static hosts")
        preview()
        self.confirm()
        self.assertEqual(Host.objects.get(pk=self.host.pk).name, "fixed")
        preview()
        self.client.post(reverse("confirm"), {
            "nonce": self.client.session["pending"]["nonce"], "replace_ack": "yes", "ledger_ack": "yes",
        })
        restored = Host.objects.get(pk=self.host.pk)
        self.assertTrue(restored.static)
        self.assertEqual(restored.name, "replacement")

    def test_archive_preview_fingerprint_covers_static_state(self):
        data = snapshot()
        self.client.post(reverse("archive-upload"), {
            "revision": 1, "archive": SimpleUploadedFile("archive.json", dumps(data).encode()),
        })
        Host.objects.filter(pk=self.host.pk).update(static=False)
        self.client.post(reverse("confirm"), {
            "nonce": self.client.session["pending"]["nonce"], "replace_ack": "yes", "ledger_ack": "yes",
        })
        self.assertFalse(Host.objects.get(pk=self.host.pk).static)
        self.assertEqual(Configuration.load().revision, 1)


class StaticMigrationTests(TransactionTestCase):
    def test_existing_host_defaults_false_without_changing_inventory(self):
        executor = MigrationExecutor(connection)
        old_target = [("inventory", "0011_configuration_bind_paths")]
        executor.migrate(old_target)
        old_apps = executor.loader.project_state(old_target).apps
        OldConfig = old_apps.get_model("inventory", "Configuration")
        OldSite = old_apps.get_model("inventory", "Site")
        OldHost = old_apps.get_model("inventory", "Host")
        OldConfig.objects.update_or_create(pk=1, defaults={"revision": 12, "soa_serial": 1234})
        OldSite.objects.update_or_create(pk=1, defaults={"name": "Site1", "g": 1})
        OldHost.objects.create(name="existing", site_id=1, row=7, column=2, notes="preserved")
        try:
            executor = MigrationExecutor(connection)
            executor.migrate(executor.loader.graph.leaf_nodes())
            host = Host.objects.get(name="existing")
            self.assertFalse(host.static)
            self.assertEqual((host.row, host.column, host.notes), (7, 2, "preserved"))
            self.assertEqual((Configuration.load().revision, Configuration.load().soa_serial), (12, 1234))
        finally:
            executor = MigrationExecutor(connection)
            executor.migrate(executor.loader.graph.leaf_nodes())


class StaticConcurrentTests(TransactionTestCase):
    def test_enable_static_and_delete_compete_for_same_revision(self):
        Configuration.load()
        Site.objects.update_or_create(pk=1, defaults={"name": "Site1", "g": 1})
        host = Host.objects.create(name="fixed", site_id=1, row=2, column=0)
        barrier = Barrier(2)
        def write(operation):
            close_old_connections()
            try:
                candidate = Host.objects.get(pk=host.pk)
                barrier.wait(timeout=10)
                if operation == "static":
                    candidate.static = True
                    save_host(candidate, 1)
                else:
                    delete_host(host.pk, 1)
                return "saved"
            except (ValidationError, OperationalError):
                return "rejected"
            finally:
                close_old_connections()
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(write, ("static", "delete")))
        self.assertCountEqual(results, ["saved", "rejected"])
        self.assertEqual(Configuration.load().revision, 2)
        remaining = Host.objects.filter(pk=host.pk).first()
        self.assertTrue(remaining is None or remaining.static)
