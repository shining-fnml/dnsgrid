from copy import deepcopy
from io import BytesIO
from unittest.mock import Mock, patch
from urllib.error import HTTPError, URLError

from django.test import SimpleTestCase, TransactionTestCase

from .exporters import desired_gandi
from .gandi import GandiClient, GandiError, plan_sync, sync
from .models import Configuration, GandiRecord, Host, Site


class FakeClient:
    def __init__(self):
        self.records = {}
        self.writes = []
        self.fail_at = None
        self.after_write = None

    def list_rrsets(self, zone):
        return deepcopy(self.records.get(zone, []))

    def _write(self, action, zone, name, kind, record=None):
        if self.fail_at == len(self.writes) + 1:
            raise GandiError("Simulated failure.")
        self.writes.append((action, zone, name, kind))
        records = self.records.setdefault(zone, [])
        records[:] = [item for item in records
                      if (item["rrset_name"], item["rrset_type"]) != (name, kind)]
        if record is not None:
            records.append(deepcopy(record))
        if self.after_write:
            self.after_write()

    def create_rrset(self, zone, record):
        self._write("create", zone, record["rrset_name"], record["rrset_type"], record)

    def update_rrset(self, zone, name, kind, record):
        self._write("update", zone, name, kind, record)

    def delete_rrset(self, zone, name, kind):
        self._write("delete", zone, name, kind)


class GandiTests(TransactionTestCase):
    def setUp(self):
        # TransactionTestCase flushes data migrations after each test.
        for group in range(1, 5):
            Site.objects.get_or_create(pk=group, defaults={"name": f"Site {group}", "g": group})
        self.config = Configuration.load()
        self.host = Host.objects.create(
            name="alpha", site=Site.objects.get(pk=1), row=2, column=3,
            vpn=True, public_export=True,
        )
        self.client = FakeClient()

    def preview(self):
        return plan_sync(client=self.client)

    def apply(self, plan=None):
        return sync(client=self.client, expected_fingerprint=(plan or self.preview())["fingerprint"])

    def owned(self):
        self.apply()
        self.client.writes.clear()

    def test_preview_creation_and_idempotent_retry(self):
        plan = self.preview()
        self.assertEqual(set(plan), {"revision", "changes", "conflicts", "fingerprint"})
        self.assertEqual(plan["changes"][0]["action"], "create")
        self.assertEqual(self.client.writes, [])
        self.assertFalse(GandiRecord.objects.exists())
        self.apply(plan)
        self.assertEqual(GandiRecord.objects.get().values, ["172.28.1.50"])
        self.apply()
        self.assertEqual(len(self.client.writes), 1)

    def test_identical_unmanaged_and_cname_collisions(self):
        record = desired_gandi()[0]
        for remote in (record, dict(record, rrset_type="CNAME", rrset_values=["elsewhere.test."])):
            self.client.records[self.config.gandi_zone] = [remote]
            plan = self.preview()
            self.assertTrue(plan["conflicts"])
            with self.assertRaises(GandiError):
                self.apply(plan)
            self.assertEqual(self.client.writes, [])
            self.assertFalse(GandiRecord.objects.exists())

    def test_managed_update_and_delete(self):
        self.owned()
        self.host.row = 3
        self.host.save()
        self.assertEqual(self.preview()["changes"][0]["action"], "update")
        self.apply()
        self.assertEqual(GandiRecord.objects.get().values, ["172.28.1.51"])
        self.host.public_export = False
        self.host.save()
        self.assertEqual(self.preview()["changes"][0]["action"], "delete")
        self.apply()
        self.assertFalse(GandiRecord.objects.exists())
        self.assertEqual(self.client.records[self.config.gandi_zone], [])

    def test_remote_edit_and_missing_managed_record_are_protected(self):
        self.owned()
        original = deepcopy(self.client.records)
        for records in (
            [dict(original[self.config.gandi_zone][0], rrset_ttl=999)],
            [dict(original[self.config.gandi_zone][0], rrset_values=["203.0.113.1"])],
            [],
        ):
            self.client.records[self.config.gandi_zone] = records
            self.assertTrue(self.preview()["conflicts"])
            with self.assertRaises(GandiError):
                self.apply()
            self.assertEqual(self.client.writes, [])
            self.assertTrue(GandiRecord.objects.exists())

    def test_zone_change_reconciles_old_zone_and_preserves_unrelated(self):
        self.owned()
        unrelated = {"rrset_name": "other", "rrset_type": "TXT",
                     "rrset_ttl": 100, "rrset_values": ['"keep"']}
        self.client.records[self.config.gandi_zone].append(unrelated)
        self.config.gandi_zone = "other.test"
        self.config.vpn_domain = "vpn.other.test"
        self.config.save()
        plan = self.preview()
        self.assertEqual({change["action"] for change in plan["changes"]}, {"create", "delete"})
        self.apply(plan)
        self.assertEqual(self.client.records["example.tld"], [unrelated])
        self.assertEqual(GandiRecord.objects.get().zone, "other.test")

    def test_partial_failure_keeps_successful_ownership(self):
        Host.objects.create(name="beta", site=Site.objects.get(pk=2), row=1, column=1,
                            vpn=True, public_export=True)
        self.client.fail_at = 2
        with self.assertRaises(GandiError):
            self.apply()
        self.assertEqual(GandiRecord.objects.count(), 1)
        self.assertEqual(GandiRecord.objects.get().name, "alpha.vpn")
        self.client.fail_at = None
        self.assertEqual(len(self.preview()["changes"]), 1)
        self.apply()
        self.assertEqual(GandiRecord.objects.count(), 2)
        self.assertEqual(len(self.client.writes), 2)

    def test_stale_remote_and_inventory_previews_are_refused(self):
        plan = self.preview()
        self.client.records["example.tld"] = [{
            "rrset_name": "unrelated", "rrset_type": "TXT",
            "rrset_ttl": 300, "rrset_values": ['"new"'],
        }]
        with self.assertRaises(GandiError):
            self.apply(plan)
        plan = self.preview()
        Configuration.objects.filter(pk=1).update(revision=self.config.revision + 1)
        with self.assertRaises(GandiError):
            self.apply(plan)
        self.assertEqual(self.client.writes, [])

    def test_stale_explicit_config_cannot_bypass_revision_guard(self):
        plan = plan_sync(self.config, [self.host], self.client)
        Configuration.objects.filter(pk=1).update(revision=self.config.revision + 1)
        with self.assertRaises(GandiError):
            sync(self.config, [self.host], self.client, expected_fingerprint=plan["fingerprint"])
        self.assertEqual(self.client.writes, [])

    def test_stale_noop_preview_is_also_refused(self):
        self.owned()
        plan = plan_sync(self.config, [self.host], self.client)
        self.assertEqual(plan["changes"], [])
        Configuration.objects.filter(pk=1).update(revision=self.config.revision + 1)
        with self.assertRaises(GandiError):
            sync(self.config, [self.host], self.client, expected_fingerprint=plan["fingerprint"])

    def test_nonpublic_vpn_and_disabled_vpn_do_not_create_remote_records(self):
        for vpn, public in ((True, False), (False, True), (False, False)):
            self.host.vpn, self.host.public_export = vpn, public
            self.host.save()
            self.assertEqual(self.preview()["changes"], [])
            self.apply()
        self.assertEqual(self.client.writes, [])

    def test_ledger_change_invalidates_preview(self):
        self.owned()
        plan = self.preview()
        GandiRecord.objects.update(ttl=600)
        with self.assertRaises(GandiError):
            self.apply(plan)
        self.assertEqual(self.client.writes, [])

    def test_revision_change_between_actions_stops_after_checkpoint(self):
        Host.objects.create(name="beta", site=Site.objects.get(pk=2), row=1, column=1,
                            vpn=True, public_export=True)
        def change_inventory():
            Configuration.objects.filter(pk=1).update(revision=self.config.revision + 1)
        self.client.after_write = change_inventory
        with self.assertRaises(GandiError):
            self.apply()
        self.assertEqual(GandiRecord.objects.count(), 1)
        self.assertEqual(len(self.client.writes), 1)

    def test_canonical_remote_order_does_not_change_fingerprint(self):
        self.client.records["example.tld"] = [
            {"rrset_name": "other", "rrset_type": "TXT", "rrset_ttl": 300,
             "rrset_values": ['"b"', '"a"']},
            {"rrset_name": "another", "rrset_type": "A", "rrset_ttl": 300,
             "rrset_values": ["203.0.113.2"]},
        ]
        plan = self.preview()
        self.client.records["example.tld"].reverse()
        self.client.records["example.tld"][1]["rrset_values"].reverse()
        self.assertEqual(plan["fingerprint"], self.preview()["fingerprint"])

    def test_remote_change_between_preview_recheck_and_write_is_refused(self):
        plan = self.preview()
        read = self.client.list_rrsets
        calls = 0
        def changed(zone):
            nonlocal calls
            calls += 1
            if calls == 2:
                self.client.records[zone] = desired_gandi()
            return read(zone)
        self.client.list_rrsets = changed
        with self.assertRaises(GandiError):
            self.apply(plan)
        self.assertEqual(self.client.writes, [])


class GandiClientTests(SimpleTestCase):
    def setUp(self):
        self.config = Mock(gandi_token="config-secret")

    @patch("inventory.gandi.request.build_opener")
    @patch.dict("os.environ", {"DNSGRID_GANDI_TOKEN": "environment-secret"})
    def test_fixed_origin_token_timeout_and_payload(self, opener):
        response = opener.return_value.open.return_value.__enter__.return_value
        response.read.return_value = b"[]"
        client = GandiClient(self.config, timeout=7)
        self.assertEqual(client.list_rrsets("example.tld"), [])
        req = opener.return_value.open.call_args.args[0]
        self.assertEqual(req.full_url, "https://api.gandi.net/v5/livedns/domains/example.tld/records")
        self.assertEqual(req.get_header("Authorization"), "Bearer " + "environment-secret")
        self.assertEqual(opener.return_value.open.call_args.kwargs["timeout"], 7)
        client.delete_rrset("example.tld", "alpha.vpn", "A")
        req = opener.return_value.open.call_args.args[0]
        self.assertTrue(req.full_url.endswith("/records/alpha.vpn/A"))
        self.assertEqual(req.method, "DELETE")

    @patch("inventory.gandi.request.build_opener")
    def test_invalid_identifiers_do_not_send_request(self, opener):
        client = GandiClient(self.config)
        for zone, name, kind in [
            ("https://evil.test", "alpha", "A"), ("example.tld", "../other", "A"),
            ("example.tld", "..", "A"), ("example.tld", "a?token=x", "A"),
            ("example.tld", "a", "A/../../"), ("example.tld", "a%2Fb", "A"),
        ]:
            with self.assertRaises(GandiError):
                client.delete_rrset(zone, name, kind)
        opener.assert_not_called()

    @patch("inventory.gandi.request.build_opener")
    @patch.dict("os.environ", {"DNSGRID_GANDI_TOKEN": ""})
    def test_config_token_fallback_and_missing_token(self, opener):
        opener.return_value.open.return_value.__enter__.return_value.read.return_value = b"[]"
        GandiClient(self.config).list_rrsets("example.tld")
        req = opener.return_value.open.call_args.args[0]
        self.assertEqual(req.get_header("Authorization"), "Bearer " + "config-secret")
        with self.assertRaises(RuntimeError):
            GandiClient(Mock(gandi_token=""))

    def test_redirects_are_not_followed(self):
        from .gandi import _NoRedirect
        self.assertIsNone(_NoRedirect().redirect_request(
            Mock(), Mock(), 302, "redirect", {}, "https://untrusted.example/"
        ))

    @patch.dict("os.environ", {"DNSGRID_GANDI_TOKEN": ""})
    def test_config_tokens_with_newlines_are_rejected_safely(self):
        for token in ("private-secret\rheader", "private-secret\nheader"):
            with self.assertRaises(GandiError) as caught:
                GandiClient(Mock(gandi_token=token))
            self.assertNotIn("private-secret", str(caught.exception))

    def test_environment_tokens_with_newlines_are_rejected_safely(self):
        with patch.dict("os.environ", {"DNSGRID_GANDI_TOKEN": "private-secret\r\nheader"}):
            with self.assertRaises(GandiError) as caught:
                GandiClient(self.config)
            self.assertNotIn("private-secret", str(caught.exception))

    @patch("inventory.gandi.request.build_opener")
    def test_request_construction_and_json_encoding_errors_are_sanitized(self, opener):
        client = GandiClient(self.config)
        with patch("inventory.gandi.request.Request", side_effect=ValueError("private-secret")):
            with self.assertRaises(GandiError) as caught:
                client.list_rrsets("example.tld")
            self.assertNotIn("private-secret", str(caught.exception))
        for failure in (ValueError("private-secret"), TypeError("private-secret")):
            with patch("inventory.gandi.json.dumps", side_effect=failure):
                with self.assertRaises(GandiError) as caught:
                    client.create_rrset("example.tld", {"rrset_name": "alpha.vpn"})
                self.assertNotIn("private-secret", str(caught.exception))
        opener.assert_not_called()

    @patch("inventory.gandi.request.build_opener")
    def test_network_json_and_http_errors_are_sanitized(self, opener):
        client = GandiClient(self.config)
        for failure in [
            HTTPError("https://api.gandi.net", 403, "config-secret",
                      {}, BytesIO(b"private-response config-secret")),
            URLError("config-secret"),
            TimeoutError("config-secret"),
        ]:
            opener.return_value.open.side_effect = failure
            with self.assertRaises(GandiError) as caught:
                client.list_rrsets("example.tld")
            self.assertNotIn("config-secret", str(caught.exception))
            self.assertNotIn("private-response", str(caught.exception))
        opener.return_value.open.side_effect = None
        opener.return_value.open.return_value.__enter__.return_value.read.return_value = b"config-secret"
        with self.assertRaises(GandiError) as caught:
            client.list_rrsets("example.tld")
        self.assertNotIn("config-secret", str(caught.exception))
