from pathlib import Path
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.contrib.staticfiles import finders
from django.test import Client, TestCase
from django.urls import reverse

from .exporters import build_exports
from .models import Configuration, Host, Site
from .services import save_host


class GridRenderingTests(TestCase):
    def setUp(self):
        user = get_user_model().objects.create_user(username="operator", is_staff=True)
        self.client.force_login(user)
        self.config = Configuration.load()

    def test_site_vpn_and_status_styles_compose_without_changing_data(self):
        hosts = []
        for site in Site.objects.all():
            for status in Host.Status.values:
                for vpn in (False, True):
                    for public in (False, True):
                        for mac in (False, True):
                            x = len(hosts) + 1
                            hosts.append(Host.objects.create(
                                name=f"host-{site.pk}-{status}-{int(vpn)}-{int(public)}-{int(mac)}",
                                site=site, row=x % 16, column=x // 16,
                                status=status, vpn=vpn, public_export=public,
                                mac=f"02:00:00:00:00:{x:02x}" if mac else "",
                                category="Descriptive metadata",
                            ))
        before = build_exports()
        response = self.client.get(reverse("grid"))
        for host in hosts:
            with self.subTest(site=host.site_id, status=host.status, vpn=host.vpn):
                name = f"({host.name})" if host.status == Host.Status.DECOMMISSIONED else host.name
                name_class = "host-name vpn-name" if host.vpn else "host-name"
                vpn_class = "vpn-address published-address" if host.public_export else "vpn-address"
                vpn_line = f'<span class="{vpn_class}">VPN {host.vpn_address(self.config)}</span>' if host.vpn else ""
                mac_line = f'<small class="mac-address">{host.mac}</small>' if host.mac else ""
                self.assertContains(response, f"""
                    <td class="occupied {host.status} site-{host.site_id}">
                      <a class="cell" href="{reverse('host-edit', args=[host.pk])}" aria-describedby="status-{host.pk}">
                        <small>x={host.x} · {host.site.name}</small>
                        <span class="{name_class}">{name}</span>
                        <span>{host.lan_address(self.config)}</span>
                        {vpn_line}
                        {mac_line}
                        <span class="visually-hidden" id="status-{host.pk}">{host.get_status_display()}</span>
                      </a>
                    </td>
                """, html=True)
                original_name = host.name
                host.refresh_from_db()
                self.assertEqual(host.name, original_name)
                self.assertEqual(host.category, "Descriptive metadata")
                self.assertEqual(host.lan_fqdn(self.config), f"{host.name}.intranet.example.tld")
                self.assertEqual(host.vpn_fqdn(self.config), f"{host.name}.vpn.example.tld")
                self.assertNotContains(response, f"<strong>{name}</strong>", html=True)
        self.assertEqual(build_exports(), before)
        self.assertNotContains(response, "Public export")
        self.assertNotContains(response, "<small>Running", html=False)

    def test_site_colors_and_legend_follow_ids_not_names_or_octets(self):
        for site in Site.objects.all():
            Host.objects.create(name=f"site-{site.pk}", site=site, row=site.pk, column=0)
        before = self.client.get(reverse("grid"))
        for site in Site.objects.all():
            self.assertContains(before, f'class="occupied running site-{site.pk}"', count=1)
            Site.objects.filter(pk=site.pk).update(name=f"Renamed & site {site.pk}", g=25 - site.pk)
        response = self.client.get(reverse("grid"))
        for site in Site.objects.all():
            with self.subTest(site=site.pk):
                self.assertContains(response, f'class="occupied running site-{site.pk}"', count=1)
                self.assertContains(response, f'<span class="site-{site.pk}">{site.pk} · Renamed &amp; site {site.pk}</span>', html=True)
                self.assertContains(response, f"x={site.pk} · Renamed &amp; site {site.pk}")
                self.assertContains(response, f"192.168.{site.g}.{site.pk}")
        for text in ("VPN names: bold", "Bold VPN address: public publication", "Unconfirmed: light gray cell", "Decommissioned: (name)"):
            self.assertContains(response, text)

    def test_empty_grid_legend_includes_all_configured_sites(self):
        response = self.client.get(reverse("grid"))
        for site in Site.objects.all():
            self.assertContains(response, f'<span class="site-{site.pk}">{site.pk} · {site.name}</span>', html=True)
        self.assertContains(response, '<td class="reserved">', count=1)
        self.assertContains(response, '<td class="empty">', count=127)

    def test_grid_css_defines_dark_ink_light_surfaces_and_name_weights(self):
        css = Path(finders.find("inventory/style.css")).read_text()
        for site_id, color in enumerate(("#153e75", "#205c32", "#8b2424", "#806000"), 1):
            self.assertIn(f".grid .site-{site_id}, .grid-legend .site-{site_id} {{ color: {color}; }}", css)
        self.assertIn(".grid .occupied, .grid-legend { background: #fff; color: #222; color-scheme: light; }", css)
        self.assertIn(".grid .occupied .cell { color: inherit; }", css)
        self.assertIn(".grid .occupied.unconfirmed { background: #e5e7eb; }", css)
        self.assertIn(".grid .occupied .cell:hover, .grid .occupied .cell:focus-visible { background: #e8eef6; }", css)
        self.assertIn("outline: 2px solid var(--accent);", css)
        self.assertIn(".grid .host-name { font-weight: normal; }", css)
        self.assertIn(".grid .host-name.vpn-name { font-weight: bold; }", css)
        self.assertIn(".grid .vpn-address { font-weight: normal; }", css)
        self.assertIn(".grid .vpn-address.published-address { font-weight: bold; }", css)

    def test_heading_enhancement_keeps_one_original_two_row_thead(self):
        response = self.client.get(reverse("grid"))
        self.assertContains(response, "<thead>", count=1)
        self.assertContains(response, '<th rowspan="2" scope="col">Row</th>', html=True)
        self.assertContains(response, "/static/inventory/grid.js")
        css = Path(finders.find("inventory/style.css")).read_text()
        script = Path(finders.find("inventory/grid.js")).read_text()
        self.assertIn(".grid-scroll { position: relative; overflow-x: auto; }", css)
        self.assertIn("z-index: 2; transform: translateY(", css)
        self.assertIn(".grid thead th { background:", css)
        self.assertIn('document.querySelector(".grid-scroll .grid")', script)
        self.assertIn("ResizeObserver", script)
        self.assertNotIn("cloneNode", script)


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

    def test_terminal_semicolon_is_stored_canonically_and_duplicates_rejected(self):
        host = self.create_host(mac=" \t00:11:22:33:44:55 ; \n")
        self.assertEqual(host.mac, "00:11:22:33:44:55")
        response = self.client.post(reverse("host-create"), self.host_data(
            name="duplicate", row=2, mac="0011.2233.4455;",
        ))
        self.assertTemplateUsed(response, "inventory/form.html")
        self.assertEqual(Host.objects.count(), 1)
        for raw in (";", "00:11:22:33:44:55;;", "00:11;22:33:44:55"):
            with self.subTest(raw=raw):
                response = self.client.post(reverse("host-create"), self.host_data(
                    name="bad", row=3, mac=raw,
                ))
                self.assertTemplateUsed(response, "inventory/form.html")
                self.assertEqual(Host.objects.count(), 1)

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

    def test_concurrent_move_during_deletion_preview_blocks_confirmation(self):
        from .views import get_object_or_404
        host = self.create_host()

        def move_after_read(*args, **kwargs):
            snapshot = get_object_or_404(*args, **kwargs)
            moved = Host.objects.get(pk=snapshot.pk)
            moved.site_id = 2
            save_host(moved, expected_revision=Configuration.load().revision)
            return snapshot

        with patch("inventory.views.get_object_or_404", side_effect=move_after_read):
            response = self.client.post(reverse("host-delete", args=[host.pk]))
        self.assertContains(response, "192.168.1.1")
        response = self.client.post(reverse("confirm"), {
            "nonce": self.client.session["pending"]["nonce"],
        }, follow=True)
        self.assertContains(response, "Stale")
        host.refresh_from_db()
        self.assertEqual(host.site_id, 2)

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
            data[f"site_{site.pk}_dsm_ifname"] = site.dsm_ifname
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

    def test_dsm_interface_settings_preview_confirm_and_validation(self):
        response = self.client.get(reverse("configuration"))
        self.assertContains(response, "Site 1 DSM DHCP interface")
        response = self.client.post(reverse("configuration"), self.settings_data(
            site_1_dsm_ifname="ovs_eth0",
        ))
        self.assertTemplateUsed(response, "inventory/confirm.html")
        self.assertContains(response, "ovs_eth0")
        self.assertEqual(Site.objects.get(pk=1).dsm_ifname, "")
        self.apply_pending()
        self.assertEqual(Site.objects.get(pk=1).dsm_ifname, "ovs_eth0")
        response = self.client.post(reverse("configuration"), self.settings_data(
            site_1_dsm_ifname="../invalid",
        ))
        self.assertTrue(response.context["form"].errors)
        self.assertEqual(Site.objects.get(pk=1).dsm_ifname, "ovs_eth0")

    def test_dsm_api_artifact_preview_download_and_stale_revision(self):
        self.create_host()
        Site.objects.filter(pk=1).update(dsm_ifname="ovs_eth0")
        response = self.client.get(reverse("exports"))
        self.assertContains(response, "DSM DHCP reservations (API)")
        self.assertContains(response, "dsm-reservations-site-1.json")
        self.assertContains(response, "dsm-request-site-1.form")
        revision = response.context["revision"]
        for filename in ("dsm-reservations-site-1.json", "dsm-request-site-1.form"):
            url = reverse("download", args=[filename]) + f"?revision={revision}"
            download = self.client.get(url)
            self.assertEqual(download.status_code, 200)
            self.assertEqual(download.content.decode(), response.context["artifacts"][filename])
        config = Configuration.load()
        config.revision += 1
        config.save(update_fields=["revision"])
        self.assertEqual(self.client.get(url).status_code, 409)
        self.assertEqual(self.client.get(reverse("download", args=[
            "dsm-reservations-site-2.json",
        ])).status_code, 404)

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
        export_page = self.client.get(reverse("exports"))
        self.assertContains(export_page, "dhcpd-dsm.conf")
        self.assertContains(export_page, "SYNO.Network.DHCPServer.Reservation.set")
        self.assertContains(export_page, "SYNO.Network.DHCPServer.Reservation.get")
        self.assertContains(export_page, "sudo python3")
        self.assertContains(export_page, "--apply")
        self.assertContains(export_page, "replaces the full reservation list")
        self.assertContains(export_page, "IPv4 only")
        self.assertContains(export_page, "Do not edit DSM system files or package services")
        dsm_download = self.client.get(reverse("download", args=["dhcpd-dsm.conf"]))
        self.assertEqual(dsm_download.status_code, 200)
        self.assertIn("dhcp-host=", dsm_download.content.decode())
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


class QuickMoveViewsTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(username="operator", is_staff=True)
        self.client.force_login(self.user)
        Configuration.load()
        self.host = Host(name="saved", site_id=3, row=2, column=0, vpn=True,
                         public_export=True, category="Keep", status=Host.Status.DECOMMISSIONED,
                         mac="02:00:00:00:00:01", notes="Saved notes")
        save_host(self.host, Configuration.load().revision)
        self.url = reverse("host-move", args=[self.host.pk])

    def snapshot(self):
        return Configuration.load().revision, list(Host.objects.values())

    def preview(self, direction="down", **updates):
        data = {"direction": direction, "revision": Configuration.load().revision}
        data.update(updates)
        return self.client.post(self.url, data)

    def confirm(self, **updates):
        data = {"nonce": self.client.session["pending"]["nonce"]}
        data.update(updates)
        return self.client.post(reverse("confirm"), data, follow=True)

    def test_controls_show_only_free_valid_neighbors_and_never_on_other_pages(self):
        for x, visible in ((1, ("down",)), (2, ("up", "down")), (15, ("up", "down")),
                           (16, ("up", "down")), (127, ("up",))):
            with self.subTest(x=x):
                Host.objects.filter(pk=self.host.pk).update(row=x % 16, column=x // 16)
                before = self.snapshot()
                response = self.client.get(reverse("host-edit", args=[self.host.pk]))
                self.assertEqual(self.snapshot(), before)
                self.assertEqual([move["direction"] for move in response.context["moves"]], list(visible))
                for direction in ("up", "down"):
                    if direction in visible:
                        target = x + (-1 if direction == "up" else 1)
                        self.assertContains(response, f'Move {direction} (x={target})')
                        self.assertContains(response, f'name="direction" value="{direction}"')
                    else:
                        self.assertNotContains(response, f'name="direction" value="{direction}"')
                self.assertContains(response, f'name="revision" value="{Configuration.load().revision}"')
        Host.objects.filter(pk=self.host.pk).update(row=2, column=0)
        for row in (1, 3):
            save_host(Host(name=f"block-{row}", site_id=1, row=row, column=0),
                      Configuration.load().revision)
        response = self.client.get(reverse("host-edit", args=[self.host.pk]))
        self.assertEqual(response.context["moves"], [])
        self.assertNotContains(response, f'action="{self.url}"')
        for page in ("host-create", "configuration"):
            response = self.client.get(reverse(page))
            self.assertNotContains(response, 'name="direction"')
            self.assertNotContains(response, "Quick moves")

    def test_preview_and_confirm_use_saved_values_ignore_forged_fields_and_apply_once(self):
        before = self.snapshot()
        response = self.preview(target=100, row=4, column=6, name="forged", site=1)
        self.assertTemplateUsed(response, "inventory/confirm.html")
        self.assertEqual(self.snapshot(), before)
        for value in ("x=2", "x=3", "192.168.3.2", "192.168.3.3", "172.28.3.2", "172.28.3.3"):
            self.assertContains(response, value)
        pending = self.client.session["pending"]
        self.assertEqual(pending["kind"], "move")
        self.assertEqual(pending["payload"], {"id": self.host.pk, "direction": "down"})
        response = self.confirm(target=127, direction="up", name="forged", site=1)
        self.assertContains(response, "Changes applied.")
        expected = before[1][0].copy()
        expected.update(row=3)
        self.assertEqual(self.snapshot(), (before[0] + 1, [expected]))
        self.assertNotIn("pending", self.client.session)
        response = self.client.post(reverse("confirm"), {"nonce": pending["nonce"]}, follow=True)
        self.assertContains(response, "confirmation expired")
        self.assertEqual(self.snapshot(), (before[0] + 1, [expected]))

    def test_invalid_or_stale_preview_and_occupied_target_do_not_mutate(self):
        for data in ({"direction": "sideways"}, {"direction": "1"}, {"direction": ""},
                     {"revision": ""}, {"revision": "invalid"}, {"revision": 0}, {"revision": 1}):
            with self.subTest(data=data):
                before = self.snapshot()
                response = self.preview(**data)
                self.assertEqual(response.status_code, 302)
                self.assertNotIn("pending", self.client.session)
                self.assertEqual(self.snapshot(), before)
        displayed_revision = Configuration.load().revision
        save_host(Host(name="blocking", site_id=1, row=3, column=0), displayed_revision)
        for revision in (displayed_revision, Configuration.load().revision):
            before = self.snapshot()
            self.preview(revision=revision)
            self.assertEqual(self.snapshot(), before)
            self.assertNotIn("pending", self.client.session)

    def test_target_taken_after_preview_rejects_stale_confirmation_without_shifting(self):
        self.preview()
        save_host(Host(name="blocking", site_id=1, row=3, column=0),
                  Configuration.load().revision)
        before = self.snapshot()
        response = self.confirm()
        self.assertContains(response, "Stale")
        self.assertEqual(self.snapshot(), before)
        self.assertNotIn("pending", self.client.session)

    def test_occupancy_is_rechecked_even_if_target_added_without_revision_change(self):
        self.preview()
        Host.objects.create(name="blocking", site_id=1, row=3, column=0)
        before = self.snapshot()
        response = self.confirm()
        self.assertContains(response, "occupied")
        self.assertEqual(self.snapshot(), before)

    def test_wrong_nonce_does_not_consume_valid_move_preview(self):
        self.preview()
        before = self.snapshot()
        nonce = self.client.session["pending"]["nonce"]
        response = self.confirm(nonce="incorrect")
        self.assertContains(response, "confirmation expired")
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(self.client.session["pending"]["nonce"], nonce)
        self.confirm()
        self.assertEqual(Configuration.load().revision, before[0] + 1)

    def test_post_only_csrf_and_operator_authorization_for_both_stages(self):
        before = self.snapshot()
        self.assertEqual(self.client.get(self.url).status_code, 405)
        self.assertEqual(self.client.get(reverse("confirm")).status_code, 405)
        csrf_client = Client(enforce_csrf_checks=True)
        csrf_client.force_login(self.user)
        self.assertEqual(csrf_client.post(self.url, {
            "direction": "down", "revision": before[0],
        }).status_code, 403)
        response = csrf_client.get(reverse("host-edit", args=[self.host.pk]))
        self.assertContains(response, 'name="csrfmiddlewaretoken"')
        token = csrf_client.cookies["csrftoken"].value
        response = csrf_client.post(self.url, {
            "direction": "down", "revision": before[0], "csrfmiddlewaretoken": token,
        })
        self.assertTemplateUsed(response, "inventory/confirm.html")
        nonce = csrf_client.session["pending"]["nonce"]
        self.assertEqual(csrf_client.post(reverse("confirm"), {"nonce": nonce}).status_code, 403)
        self.assertEqual(self.snapshot(), before)
        for url in (self.url, reverse("confirm")):
            self.assertEqual(Client().post(url).status_code, 302)
        self.user.is_staff = False
        self.user.save()
        for url in (self.url, reverse("confirm")):
            self.assertEqual(self.client.post(url).status_code, 403)
        self.assertEqual(self.snapshot(), before)
