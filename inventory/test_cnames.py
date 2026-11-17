import copy
from pathlib import Path
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.contrib.staticfiles import finders
from django.core.exceptions import ValidationError
from django.db import connection
from django.db.migrations.executor import MigrationExecutor
from django.test import TestCase, TransactionTestCase
from django.urls import reverse

from .archives import MAX_LEDGER, restore, snapshot, validate
from .exporters import build_exports, desired_gandi
from .gandi import plan_sync, sync
from .models import Configuration, GandiRecord, Host
from .services import save_host
from .test_gandi import FakeClient


class CnameTests(TestCase):
    def setUp(self):
        self.config = Configuration.load()
        self.host = Host(name="alpha", cnames=["printer", "web"], site_id=1,
                         row=1, column=0, vpn=True, public_export=True)
        save_host(self.host, self.config.revision)

    def test_namespace_rejects_case_insensitive_collisions_in_both_directions(self):
        for name, aliases in (
            ("another", ["PrInTeR"]),
            ("printer", []),
            ("another", ["ALPHA"]),
            ("another", ["another"]),
            ("another", ["new", "NEW"]),
            ("another", ["bad.example"]),
        ):
            host = Host(name=name, cnames=aliases, site_id=1, row=2, column=0)
            with self.subTest(name=name, aliases=aliases), self.assertRaises(ValidationError):
                save_host(host, Configuration.load().revision)
        self.host.cnames = [" WEB ", "Printer"]
        save_host(self.host, Configuration.load().revision)
        self.assertEqual(self.host.cnames, ["printer", "web"])

    def test_zone_exports_and_public_flags(self):
        for vpn, public in ((False, False), (False, True), (True, False), (True, True)):
            self.host.vpn = vpn
            self.host.public_export = public
            exports = build_exports(self.config, [self.host])
            self.assertIn("printer.intranet.example.tld. 300 CNAME alpha.intranet.example.tld.",
                          exports["forward.zone"])
            self.assertEqual("printer.vpn. 300 CNAME alpha.vpn." in exports["vpn.zone"], vpn)
            self.assertNotIn(" CNAME ", exports["reverse-vpn.zone"])
            records = desired_gandi(self.config, [self.host])
            cnames = [item for item in records if item["rrset_type"] == "CNAME"]
            if vpn and public:
                self.assertEqual(
                    {(item["rrset_name"], item["rrset_values"][0]) for item in cnames},
                    {("printer.intranet", "alpha.intranet.example.tld."),
                     ("web.intranet", "alpha.intranet.example.tld."),
                     ("printer.vpn", "alpha.vpn.example.tld."),
                     ("web.vpn", "alpha.vpn.example.tld.")},
                )
            else:
                self.assertEqual(cnames, [])

    def test_add_remove_alias_advances_serial_and_move_retains_aliases(self):
        previous = Configuration.load()
        self.host.cnames = ["printer"]
        save_host(self.host, previous.revision)
        current = Configuration.load()
        self.assertGreater(current.soa_serial, previous.soa_serial)
        self.host.row = 2
        save_host(self.host, current.revision)
        self.host.refresh_from_db()
        self.assertEqual(self.host.cnames, ["printer"])
        self.assertNotIn("web.", build_exports()["forward.zone"])

    def test_archive_roundtrip_and_legacy_import(self):
        GandiRecord.objects.create(zone="example.tld", name="printer.intranet",
                                   record_type="CNAME", values=["alpha.intranet.example.tld."], ttl=300)
        data = snapshot()
        self.assertEqual(validate(data), data)
        restore(data, Configuration.load().revision)
        self.assertEqual(Host.objects.get(pk=self.host.pk).cnames, ["printer", "web"])
        self.assertEqual(GandiRecord.objects.get().record_type, "CNAME")
        for version in (1, 2):
            legacy = copy.deepcopy(data)
            legacy["schema_version"] = version
            legacy["gandi_records"] = []
            legacy["hosts"][0].pop("cnames")
            if version == 1:
                legacy["hosts"][0].pop("static")
            self.assertEqual(validate(legacy)["hosts"][0]["cnames"], [])

    def test_archive_validates_cname_types_collisions_and_lan_ownership(self):
        data = snapshot()
        data["gandi_records"] = [{
            "id": 20, "zone": "example.tld", "name": "retired.intranet",
            "record_type": "A", "values": ["192.168.1.1"], "ttl": 300,
        }]
        self.assertEqual(validate(data)["gandi_records"], data["gandi_records"])
        for aliases in (["alpha"], ["printer", "PRINTER"], ["bad.example"], [1], "printer"):
            candidate = copy.deepcopy(data)
            candidate["hosts"][0]["cnames"] = aliases
            with self.subTest(aliases=aliases), self.assertRaises(ValidationError):
                validate(candidate)

    def test_gandi_sync_tracks_cnames_and_reconciles_managed_type_transition(self):
        client = FakeClient()
        plan = plan_sync(client=client)
        sync(client=client, expected_fingerprint=plan["fingerprint"])
        self.assertEqual(GandiRecord.objects.filter(record_type="CNAME").count(), 4)
        self.assertEqual(plan_sync(client=client)["changes"], [])

        self.host.name = "renamed"
        self.host.cnames = ["alpha"]
        save_host(self.host, Configuration.load().revision)
        plan = plan_sync(client=client)
        self.assertFalse(plan["conflicts"])
        actions = [(change["action"], change["name"], change["type"]) for change in plan["changes"]]
        self.assertLess(actions.index(("delete", "alpha.vpn", "A")),
                        actions.index(("create", "alpha.vpn", "CNAME")))
        sync(client=client, expected_fingerprint=plan["fingerprint"])
        self.assertEqual(GandiRecord.objects.get(name="alpha.vpn").record_type, "CNAME")
        self.assertEqual(plan_sync(client=client)["changes"], [])
        self.host.name = "alpha"
        self.host.cnames = []
        save_host(self.host, Configuration.load().revision)
        plan = plan_sync(client=client)
        self.assertFalse(plan["conflicts"])
        actions = [(change["action"], change["name"], change["type"]) for change in plan["changes"]]
        self.assertLess(actions.index(("delete", "alpha.vpn", "CNAME")),
                        actions.index(("create", "alpha.vpn", "A")))
        sync(client=client, expected_fingerprint=plan["fingerprint"])
        self.assertEqual(GandiRecord.objects.get(name="alpha.vpn").record_type, "A")

    def test_gandi_refuses_unmanaged_or_remotely_changed_collisions(self):
        client = FakeClient()
        client.records["example.tld"] = [{
            "rrset_name": "printer.vpn", "rrset_type": "TXT",
            "rrset_values": ["unmanaged"], "rrset_ttl": 300,
        }]
        self.assertTrue(plan_sync(client=client)["conflicts"])
        self.assertEqual(client.writes, [])
        client.records.clear()
        plan = plan_sync(client=client)
        sync(client=client, expected_fingerprint=plan["fingerprint"])
        for record in client.records["example.tld"]:
            if record["rrset_name"] == "alpha.vpn":
                record["rrset_values"] = ["203.0.113.1"]
        self.host.name = "renamed"
        self.host.cnames = ["alpha"]
        save_host(self.host, Configuration.load().revision)
        self.assertTrue(plan_sync(client=client)["conflicts"])

    def test_gandi_does_not_assume_a_relative_target_is_absolute(self):
        client = FakeClient()
        plan = plan_sync(client=client)
        sync(client=client, expected_fingerprint=plan["fingerprint"])
        for record in client.records["example.tld"]:
            if record["rrset_name"] == "printer.vpn":
                record["rrset_values"] = ["alpha.vpn.example.tld"]
        self.assertTrue(plan_sync(client=client)["conflicts"])


class CnameViewTests(TestCase):
    def setUp(self):
        self.client.force_login(get_user_model().objects.create_user(username="operator", is_staff=True))
        self.host = Host.objects.create(name="alpha", site_id=1, row=1, column=0,
                                        vpn=True, cnames=["one", "two"])

    def data(self, cnames):
        return {
            "name": "alpha", "cnames": cnames, "site": 1, "row": 1, "column": 0,
            "category": "", "status": "running", "vpn": "on", "mac": "", "notes": "",
            "revision": Configuration.load().revision,
        }

    def test_grid_and_preview_then_remove(self):
        response = self.client.get(reverse("grid"))
        self.assertContains(response, '<span class="host-cnames">one - two</span>', html=True)
        self.assertContains(response, '<span class="host-name vpn-name">alpha</span>', html=True)
        css = Path(finders.find("inventory/style.css")).read_text()
        self.assertIn(".grid .host-cnames { font-style: italic; font-weight: normal; white-space: nowrap; }", css)
        response = self.client.post(reverse("host-edit", args=[self.host.pk]), self.data("one"))
        self.assertContains(response, "cnames")
        self.host.refresh_from_db()
        self.assertEqual(self.host.cnames, ["one", "two"])
        self.client.post(reverse("confirm"), {"nonce": self.client.session["pending"]["nonce"]})
        self.host.refresh_from_db()
        self.assertEqual(self.host.cnames, ["one"])
        self.client.post(reverse("host-edit", args=[self.host.pk]), self.data(""))
        self.client.post(reverse("confirm"), {"nonce": self.client.session["pending"]["nonce"]})
        self.host.refresh_from_db()
        self.assertEqual(self.host.cnames, [])

    def test_archive_download_does_not_offer_an_unrestorable_oversized_ledger(self):
        data = snapshot()
        data["gandi_records"] = [{}] * (MAX_LEDGER + 1)
        with patch("inventory.archives.snapshot", return_value=data):
            response = self.client.get(reverse("archive-download"), {"revision": 1})
        self.assertEqual(response.status_code, 400)
        self.assertContains(response, "exceeds the archive limits", status_code=400)


class CnameMigrationTests(TransactionTestCase):
    def test_existing_hosts_and_owned_records_survive_migration(self):
        executor = MigrationExecutor(connection)
        self.addCleanup(lambda: MigrationExecutor(connection).migrate(
            MigrationExecutor(connection).loader.graph.leaf_nodes(),
        ))
        old_target = [("inventory", "0015_gandi_token_expiry")]
        executor.migrate(old_target)
        old_apps = executor.loader.project_state(old_target).apps
        old_apps.get_model("inventory", "Site").objects.update_or_create(
            pk=1, defaults={"name": "Site 1", "g": 1},
        )
        old_apps.get_model("inventory", "Host").objects.create(
            name="existing", site_id=1, row=1, column=0, notes="keep",
        )
        old_apps.get_model("inventory", "GandiRecord").objects.create(
            zone="example.tld", name="existing.vpn", record_type="A",
            values=["172.28.1.1"], ttl=300,
        )
        try:
            executor = MigrationExecutor(connection)
            executor.migrate(executor.loader.graph.leaf_nodes())
            host = Host.objects.get(name="existing")
            self.assertEqual((host.cnames, host.notes), ([], "keep"))
            self.assertEqual(GandiRecord.objects.get().values, ["172.28.1.1"])
        finally:
            executor = MigrationExecutor(connection)
            executor.migrate(executor.loader.graph.leaf_nodes())
