from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import Client, TestCase
from django.urls import reverse

from .models import Configuration, Host, Site
from .services import save_host


class OperatorViewsTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(
            username="operator", is_staff=True,
        )
        self.client.force_login(self.user)
        self.config = Configuration.load()

    def host_data(self, **updates):
        data = {
            "name": "router", "site": 1, "row": 1, "column": 0,
            "category": "Networking", "status": "running", "vpn": True,
            "public_export": False, "mac": "02-AA-BB-CC-DD-EE",
            "notes": "Test host", "revision": Configuration.load().revision,
        }
        data.update(updates)
        return data

    def apply_pending(self):
        return self.client.post(reverse("confirm"), {
            "nonce": self.client.session["pending"]["nonce"],
        })

    def create_host(self, **updates):
        response = self.client.post(reverse("host-create"), self.host_data(**updates))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "inventory/confirm.html")
        self.assertEqual(self.apply_pending().status_code, 302)
        return Host.objects.get(name=updates.get("name", "router"))

    def test_requires_login_and_operator_privilege(self):
        anonymous = Client()
        self.assertEqual(anonymous.get(reverse("grid")).status_code, 302)
        self.user.is_staff = False
        self.user.save()
        for url in ("grid", "host-create", "configuration", "exports"):
            self.assertEqual(self.client.get(reverse(url)).status_code, 403)
        self.assertEqual(self.client.post(reverse("confirm")).status_code, 403)

    def test_csrf_protects_mutations(self):
        csrf_client = Client(enforce_csrf_checks=True)
        csrf_client.force_login(self.user)
        self.assertEqual(csrf_client.post(reverse("host-create"), self.host_data()).status_code, 403)
        self.assertFalse(Host.objects.exists())

    def test_grid_has_128_cells_and_reserved_zero(self):
        response = self.client.get(reverse("grid"))
        self.assertEqual(sum(len(row["cells"]) for row in response.context["rows"]), 128)
        self.assertContains(response, "0 · Reserved")
        self.assertContains(response, "0 / 127 positions")

    def test_preview_does_not_mutate_and_confirmation_normalizes_mac(self):
        response = self.client.post(reverse("host-create"), self.host_data())
        self.assertContains(response, "192.168.1.1")
        self.assertFalse(Host.objects.exists())
        self.assertEqual(Configuration.load().revision, self.config.revision)
        self.apply_pending()
        host = Host.objects.get()
        self.assertEqual(host.mac, "02:aa:bb:cc:dd:ee")
        self.assertEqual(host.x, 1)

    def test_insert_diff_shifts_and_site_move_keeps_position(self):
        first = self.create_host()
        response = self.client.post(reverse("host-create"), self.host_data(
            name="replacement", mac="", status="decommissioned",
        ))
        self.assertContains(response, "192.168.1.2")
        first.refresh_from_db()
        self.assertEqual(first.row, 1)
        self.apply_pending()
        first.refresh_from_db()
        self.assertEqual(first.row, 2)
        data = self.host_data(name=first.name, row=2, site=2, status="unconfirmed")
        self.client.post(reverse("host-edit", args=[first.pk]), data)
        self.apply_pending()
        first.refresh_from_db()
        self.assertEqual(first.x, 2)
        self.assertEqual(first.lan_address(Configuration.load()), "192.168.2.2")

    def test_invalid_cell_and_name_show_errors(self):
        for changes in ({"row": 0}, {"name": "bad; injected"}, {"mac": "ff:ff:ff:ff:ff:ff"}):
            response = self.client.post(reverse("host-create"), self.host_data(**changes))
            self.assertTemplateUsed(response, "inventory/form.html")
            self.assertTrue(response.context["form"].errors)
        self.assertFalse(Host.objects.exists())

    def test_stale_confirmation_and_wrong_nonce_cannot_apply(self):
        self.client.post(reverse("host-create"), self.host_data())
        pending = self.client.session["pending"]
        response = self.client.post(reverse("confirm"), {"nonce": "not-the-preview"})
        self.assertEqual(response.status_code, 302)
        self.assertFalse(Host.objects.exists())
        other = Host(name="other", site=Site.objects.get(pk=2), row=3, column=1)
        save_host(other, expected_revision=Configuration.load().revision)
        response = self.client.post(reverse("confirm"), {"nonce": pending["nonce"]}, follow=True)
        self.assertContains(response, "Stale")
        self.assertFalse(Host.objects.filter(name="router").exists())

    def test_delete_is_post_preview_then_confirmation_without_compaction(self):
        host = self.create_host()
        other = Host(name="other", site_id=1, row=2, column=0)
        save_host(other, expected_revision=Configuration.load().revision)
        url = reverse("host-delete", args=[host.pk])
        self.assertEqual(self.client.get(url).status_code, 405)
        self.client.post(url)
        self.assertTrue(Host.objects.filter(pk=host.pk).exists())
        self.apply_pending()
        self.assertFalse(Host.objects.filter(pk=host.pk).exists())
        other.refresh_from_db()
        self.assertEqual(other.row, 2)

    def settings_data(self, **updates):
        config = Configuration.load()
        data = {
            field: getattr(config, field) for field in (
                "lan_domain", "vpn_domain", "lan_prefix", "vpn_prefix",
                "gandi_zone", "ttl", "soa_ns", "soa_mailbox", "revision",
            )
        }
        for site in Site.objects.all():
            data[f"site_{site.pk}_name"] = site.name
            data[f"site_{site.pk}_g"] = site.g
        data.update(updates)
        return data

    def test_settings_token_never_rendered_and_blank_preserves_it(self):
        # A synthetic sentinel, not a credential.
        sentinel = "ui-redaction-sentinel"
        self.config.gandi_token = sentinel
        self.config.save()
        response = self.client.get(reverse("configuration"))
        self.assertNotContains(response, sentinel)
        response = self.client.post(reverse("configuration"), self.settings_data(
            gandi_token="", site_1_g=21,
        ))
        self.assertTemplateUsed(response, "inventory/confirm.html")
        self.assertNotContains(response, sentinel)
        self.assertEqual(Site.objects.get(pk=1).g, 1)
        self.apply_pending()
        self.assertEqual(Configuration.load().gandi_token, sentinel)
        self.assertEqual(Site.objects.get(pk=1).g, 21)

    def test_settings_show_addresses_and_reject_duplicate_sites(self):
        self.create_host()
        response = self.client.post(reverse("configuration"), self.settings_data(site_1_g=11))
        self.assertContains(response, "192.168.11.1 / 172.28.11.1")
        response = self.client.post(reverse("configuration"), self.settings_data(site_1_g=2))
        self.assertTrue(response.context["form"].errors)
        self.assertEqual(Site.objects.get(pk=1).g, 1)

    def test_notes_are_escaped_and_exports_hide_status_and_notes(self):
        host = self.create_host(notes="<script>alert(1)</script>", status="decommissioned")
        response = self.client.get(reverse("host-edit", args=[host.pk]))
        self.assertContains(response, "&lt;script&gt;")
        response = self.client.get(reverse("exports"))
        self.assertContains(response, "router.intranet.example.tld")
        for content in response.context["artifacts"].values():
            self.assertNotIn("decommissioned", content)
            self.assertNotIn("<script>", content)
        download = self.client.get(reverse("download", args=["dhcpd.conf"]))
        self.assertEqual(download.status_code, 200)
        self.assertIn("attachment;", download["Content-Disposition"])
        self.assertEqual(self.client.get(reverse("download", args=["not-an-artifact"])).status_code, 404)

    def test_download_rejects_stale_preview_revision(self):
        response = self.client.get(reverse("exports"))
        revision = response.context["revision"]
        self.create_host()
        url = reverse("download", args=["forward.zone"])
        self.assertEqual(self.client.get(url, {"revision": revision}).status_code, 409)
        self.assertEqual(self.client.get(url, {"revision": Configuration.load().revision}).status_code, 200)

    @patch("inventory.gandi.plan_sync")
    def test_gandi_preview_conflicts_block_confirmation(self, plan_sync):
        plan_sync.return_value = {
            "revision": 1, "changes": [], "conflicts": ["Unmanaged record collision"],
            "fingerprint": "preview",
        }
        response = self.client.post(reverse("gandi-preview"))
        self.assertContains(response, "Gandi sync blocked")
        self.assertNotIn("pending", self.client.session)

    @patch("inventory.gandi.sync")
    @patch("inventory.gandi.plan_sync")
    def test_gandi_confirmation_uses_server_side_preview(self, plan_sync, sync):
        plan_sync.return_value = {
            "revision": 1, "changes": [], "conflicts": [], "fingerprint": "preview",
        }
        self.client.post(reverse("gandi-preview"))
        sync.assert_not_called()
        self.apply_pending()
        sync.assert_called_once_with(expected_fingerprint="preview")

    @patch("inventory.gandi.plan_sync")
    def test_gandi_failure_is_reported_without_provider_details(self, plan_sync):
        from .gandi import GandiError
        plan_sync.side_effect = GandiError("provider-detail-sentinel")
        response = self.client.post(reverse("gandi-preview"), follow=True)
        self.assertContains(response, "Could not preview Gandi")
        self.assertNotContains(response, "provider-detail-sentinel")
