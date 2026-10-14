import copy
import hashlib
import io
import json
from unittest.mock import patch

from django.core.exceptions import ValidationError
from django.core.management import call_command
from django.db.migrations.executor import MigrationExecutor
from django.db import connection
from django.test import RequestFactory, TestCase, TransactionTestCase

from . import dhcp, dhcp_api
from .archives import restore, snapshot
from .models import Configuration, DHCPPublication, DHCPResult, DHCPState, Host, Site


class DHCPTests(TestCase):
    def setUp(self):
        self.config = Configuration.load()
        self.site = Site.objects.get(pk=1)
        self.site.dsm_ifname = "ovs_eth0"
        self.site.g = 17
        self.site.save()
        self.host = Host.objects.create(
            name="alpha", site=self.site, row=1, column=0, mac="02:00:00:00:00:01",
        )
        self.factory = RequestFactory()
        self.token = dhcp.rotate_token(self.site.pk)

    def publish(self, authorized=False):
        revision = Configuration.load().revision
        return dhcp.publish(revision, dhcp.preview(revision), authorized)[0]

    def get(self, token=None, **extra):
        return dhcp_api.latest(self.factory.get(
            "/", HTTP_AUTHORIZATION="Bearer " + (self.token if token is None else token), **extra,
        ), self.site.pk)

    def report(self, publication, status="applied", **extra):
        return {
            "schema_version": 1, "version": publication.version, "sha256": publication.sha256,
            "status": status, **extra,
        }

    def post(self, data, token=None, **extra):
        body = data if isinstance(data, bytes) else json.dumps(data).encode()
        return dhcp_api.result(self.factory.post(
            "/", body, content_type="application/json",
            HTTP_AUTHORIZATION="Bearer " + (self.token if token is None else token), **extra,
        ), self.site.pk)

    def test_explicit_snapshot_actual_payload_hash_and_static_exclusion(self):
        Host.objects.create(
            name="static", site=self.site, row=2, column=0, static=True,
            mac="02:00:00:00:00:02",
        )
        self.assertFalse(DHCPPublication.objects.exists())
        rows = dhcp.preview(1)
        self.assertEqual(rows[0]["subnet"], "192.168.17.0/24")
        self.assertEqual(rows[0]["payload"], {
            "ifname": "ovs_eth0", "reservationData": [{
                "mac": self.host.mac, "ip": "192.168.17.1", "hostname": "alpha",
            }],
        })
        publication = dhcp.publish(1, rows)[0]
        canonical = json.dumps(publication.payload, sort_keys=True, separators=(",", ":"),
                               ensure_ascii=True).encode("ascii")
        self.assertEqual(publication.sha256, hashlib.sha256(canonical).hexdigest())
        self.assertEqual(publication.version, f"{publication.pk}-{publication.sha256}")
        self.host.name = "edited"
        self.host.save()
        self.assertEqual(json.loads(self.get().content)["payload"], publication.payload)
        self.assertTrue(dhcp.status_rows()[0]["pending"])
        self.assertEqual(Configuration.load().revision, 1)
        self.assertEqual(Configuration.load().soa_serial, self.config.soa_serial)
        with self.assertRaises(ValidationError):
            publication.save()

    def test_no_configured_sites_and_site_membership_not_octet_identity(self):
        second = Site.objects.get(pk=2)
        second.dsm_ifname = "bond0"
        second.g = 41
        second.save()
        Host.objects.create(
            name="beta", site=second, row=2, column=0, mac="02:00:00:00:00:02",
        )
        rows = dhcp.preview(1)
        self.assertEqual([row["site_id"] for row in rows], [1, 2])
        self.assertEqual(rows[1]["payload"]["reservationData"][0]["ip"], "192.168.41.2")
        Site.objects.update(dsm_ifname="")
        self.assertEqual(dhcp.preview(1), [])

    def test_idempotence_stale_revision_preview_and_competing_publication(self):
        rows = dhcp.preview(1)
        first = dhcp.publish(1, rows)[0]
        with self.assertRaises(ValidationError):
            dhcp.publish(1, rows)
        self.assertEqual(self.publish().pk, first.pk)
        with self.assertRaises(ValidationError):
            dhcp.preview(2)
        rows = dhcp.preview(1)
        forged = copy.deepcopy(rows)
        forged[0]["payload"]["ifname"] = "different"
        with self.assertRaises(ValidationError):
            dhcp.publish(1, forged)
        forged = copy.deepcopy(rows)
        forged[0]["site_id"] = True
        with self.assertRaises(ValidationError):
            dhcp.publish(1, forged)
        Configuration.objects.update(revision=2)
        with self.assertRaises(ValidationError):
            dhcp.publish(1, rows)
        self.assertEqual(DHCPPublication.objects.count(), 1)

    def test_all_site_validation_and_authorization_before_insert(self):
        second = Site.objects.get(pk=2)
        second.dsm_ifname = "invalid/interface"
        second.save()
        with self.assertRaises(ValidationError):
            dhcp.preview(1)
        self.assertEqual(DHCPPublication.objects.count(), 0)
        second.dsm_ifname = "eth1"
        second.save()
        rows = dhcp.preview(1)
        self.assertTrue(rows[1]["destructive"])
        with self.assertRaises(ValidationError):
            dhcp.publish(1, rows)
        self.assertEqual(DHCPPublication.objects.count(), 0)
        self.assertEqual(len(dhcp.publish(1, rows, True)), 2)

    def test_corrupt_payload_fields_are_not_published(self):
        for prefix in ("bad", "999.0", "010.20"):
            Configuration.objects.update(lan_prefix=prefix)
            with self.assertRaises(ValidationError):
                dhcp.preview(1)
        Configuration.objects.update(lan_prefix="192.168")
        self.host.mac = "invalid"
        self.host.save()
        with self.assertRaises(ValidationError):
            dhcp.preview(1)
        self.host.mac = "02:00:00:00:00:01"
        self.host.name = "invalid hostname"
        self.host.save()
        with self.assertRaises(ValidationError):
            dhcp.preview(1)
        self.assertFalse(DHCPPublication.objects.exists())

    def test_duplicate_and_out_of_subnet_payload_addresses_fail_closed(self):
        good = dhcp.preview(1)[0]["payload"]
        for address in ("192.168.17.0", "192.168.17.255", "192.168.23.1"):
            invalid = copy.deepcopy(good)
            invalid["reservationData"][0]["ip"] = address
            with patch("inventory.dhcp.reservation_payload", return_value=invalid):
                with self.assertRaises(ValidationError):
                    dhcp.preview(1)
        invalid = copy.deepcopy(good)
        invalid["reservationData"].append(dict(
            invalid["reservationData"][0], mac="02:00:00:00:00:02", hostname="beta",
        ))
        with patch("inventory.dhcp.reservation_payload", return_value=invalid):
            with self.assertRaises(ValidationError):
                dhcp.preview(1)

    def test_safe_diagnostic_codes_retained_unknown_text_sanitized(self):
        publication = self.publish()
        self.post(self.report(publication, "failed", diagnostic="verification_failed"))
        self.assertEqual(DHCPResult.objects.get().diagnostic, "verification_failed")

    def test_same_version_failure_is_visible_after_success_and_duplicate_cycles(self):
        publication = self.publish()
        self.post(self.report(publication))
        self.post(self.report(publication, "failed", diagnostic="dsm_failed"))
        failed = DHCPResult.objects.get(status="failed")
        self.assertEqual(dhcp.status_rows()[0]["status"], "failed")
        self.post(self.report(publication))
        self.post(self.report(publication, "failed"))
        self.assertEqual(dhcp.status_rows()[0]["status"], "failed")
        self.assertEqual(DHCPResult.objects.get(status="failed").received_at, failed.received_at)
        self.assertEqual(DHCPResult.objects.count(), 2)
        replacement = self.publish(True)
        self.assertNotEqual(replacement.version, publication.version)
        self.assertEqual(dhcp.status_rows()[0]["status"], "pending")

    def test_empty_payload_subnet_metadata_change_is_pending(self):
        Host.objects.all().delete()
        old = self.publish(True)
        Configuration.objects.update(lan_prefix="10.24")
        self.assertTrue(dhcp.status_rows()[0]["pending"])
        new = self.publish(True)
        self.assertEqual(old.sha256, new.sha256)
        self.assertNotEqual(old.version, new.version)
        self.assertNotEqual(old.subnet, new.subnet)

    def test_archive_restore_preserves_tokens_and_history_same_mapping(self):
        publication = self.publish()
        self.get()
        self.post(self.report(publication))
        before = DHCPState.objects.get(site=self.site)
        archive = snapshot()
        self.assertNotIn("dhcp", archive)
        restore(archive, 1)
        state = DHCPState.objects.get(site=self.site)
        self.assertEqual(state.token_sha256, before.token_sha256)
        self.assertEqual(state.latest_id, publication.pk)
        self.assertEqual(state.applied_id, publication.pk)
        self.assertEqual(state.downloaded_id, publication.pk)
        self.assertEqual(self.get().status_code, 200)

    def test_restore_reconfigured_mapping_blocks_delivery_but_drains_historical_ack(self):
        for field, value in (("g", 23), ("dsm_ifname", "bond0")):
            with self.subTest(field=field):
                publication = self.publish()
                archive = snapshot()
                archive["sites"][0][field] = value
                restore(archive, Configuration.load().revision)
                self.assertTrue(DHCPPublication.objects.filter(pk=publication.pk).exists())
                response = self.get(HTTP_IF_NONE_MATCH=f'"{publication.version}"')
                self.assertEqual(response.status_code, 409)
                self.assertEqual(json.loads(response.content), {"error": "mapping_changed"})
                self.assertEqual(dhcp.status_rows()[0]["status"], "mapping_changed")
                self.assertEqual(self.post(self.report(publication)).status_code, 200)
                replacement = self.publish()
                self.assertNotEqual(publication.version, replacement.version)
                self.assertEqual(self.get().status_code, 200)
                self.assertEqual(self.post(self.report(replacement)).status_code, 200)

    def test_prefix_reconfiguration_blocks_historical_delivery(self):
        publication = self.publish()
        Configuration.objects.update(lan_prefix="10.24")
        self.assertEqual(self.get().status_code, 409)
        self.assertEqual(self.post(self.report(publication)).status_code, 200)
        self.assertTrue(DHCPPublication.objects.filter(pk=publication.pk).exists())

    def test_empty_and_less_than_half_requires_authorization(self):
        for row in range(2, 5):
            Host.objects.create(
                name=f"host-{row}", site=self.site, row=row, column=0,
                mac=f"02:00:00:00:00:0{row}",
            )
        self.publish()
        Host.objects.filter(row__gte=3).delete()
        self.assertFalse(dhcp.preview(1)[0]["destructive"])
        Host.objects.filter(row=2).delete()
        self.assertTrue(dhcp.preview(1)[0]["destructive"])
        with self.assertRaises(ValidationError):
            self.publish()
        self.publish(True)
        Host.objects.all().delete()
        with self.assertRaises(ValidationError):
            self.publish()
        self.publish(True)
        with self.assertRaises(ValidationError):
            self.publish("yes")

    def test_authorization_change_new_version_same_content_and_rejected_retry(self):
        original = self.publish()
        self.post(self.report(original, "rejected"))
        authorized = self.publish(True)
        self.assertEqual(original.sha256, authorized.sha256)
        self.assertNotEqual(original.version, authorized.version)
        self.assertFalse(original.destructive_authorized)
        self.assertTrue(authorized.destructive_authorized)
        self.assertEqual(self.publish(True).pk, authorized.pk)
        self.assertEqual(DHCPPublication.objects.get(pk=original.pk).payload, original.payload)

    def test_machine_auth_is_site_scoped_revocable_and_ignores_session(self):
        self.assertEqual(self.get("wrong").status_code, 401)
        request = self.factory.get("/")
        request.session = {"authenticated": True}
        self.assertEqual(dhcp_api.latest(request, self.site.pk).status_code, 401)
        other = dhcp.rotate_token(2)
        self.assertEqual(self.get(other).status_code, 401)
        new = dhcp.rotate_token(1)
        self.assertEqual(self.get().status_code, 401)
        self.assertEqual(self.get(new).status_code, 404)
        dhcp.rotate_token(1, revoke=True)
        self.assertEqual(self.get(new).status_code, 401)
        self.assertTrue(dhcp_api.result.csrf_exempt)
        self.assertFalse(getattr(dhcp_api.latest, "csrf_exempt", False))

    def test_token_command_prints_once_only_verifier_stored(self):
        output = io.StringIO()
        call_command("dhcp_token", 1, stdout=output)
        token = output.getvalue().strip()
        self.assertGreaterEqual(len(token), 40)
        state = DHCPState.objects.get(site=self.site)
        self.assertEqual(state.token_sha256, hashlib.sha256(token.encode()).hexdigest())
        self.assertNotIn(token, str(state.__dict__))
        output = io.StringIO()
        call_command("dhcp_token", 1, revoke=True, stdout=output)
        self.assertEqual(output.getvalue(), "Token revoked.\n")
        self.assertEqual(DHCPState.objects.get(site=self.site).token_sha256, "")

    def test_latest_contract_etag_contact_download_not_applied(self):
        response = self.get()
        self.assertEqual(response.status_code, 404)
        self.assertEqual(json.loads(response.content), {"error": "no_publication"})
        publication = self.publish()
        response = self.get()
        body = json.loads(response.content)
        self.assertEqual(set(body), {
            "schema_version", "site_id", "subnet", "version", "sha256", "published_at",
            "destructive_authorized", "payload",
        })
        self.assertEqual(body, dhcp.envelope(publication))
        self.assertEqual(response["ETag"], f'"{publication.version}"')
        self.assertEqual(response["Cache-Control"], "private, no-store")
        state = DHCPState.objects.get(site=self.site)
        self.assertIsNotNone(state.contacted_at)
        self.assertIsNotNone(state.downloaded_at)
        self.assertEqual(state.downloaded_id, publication.pk)
        self.assertIsNone(state.applied_id)
        row = dhcp.status_rows()[0]
        self.assertEqual(row["subnet"], "192.168.17.0/24")
        self.assertEqual(row["downloaded"], publication)
        self.assertEqual(row["last_seen"], state.contacted_at)
        self.assertEqual(row["last_downloaded_at"], state.downloaded_at)
        self.assertEqual(row["history"], [publication])
        conditional = self.get(HTTP_IF_NONE_MATCH=response["ETag"])
        self.assertEqual(conditional.status_code, 304)
        self.assertEqual(conditional["ETag"], response["ETag"])
        self.assertEqual(conditional.content, b"")

    def test_result_schema_exact_checksum_version_and_sanitized_diagnostic(self):
        publication = self.publish()
        valid = self.report(publication)
        variants = [
            {**valid, "schema_version": True}, {**valid, "schema_version": 2},
            {**valid, "status": "downloaded"}, {**valid, "status": []},
            {**valid, "sha256": "a" * 64}, {**valid, "version": "unknown"},
            {**valid, "site_id": 1}, {**valid, "diagnostic": {}},
            {key: value for key, value in valid.items() if key != "version"},
            [], b"{", b"\xff",
        ]
        for data in variants:
            with self.subTest(data=data):
                self.assertEqual(self.post(data).status_code, 400)
        self.assertEqual(DHCPResult.objects.count(), 0)
        self.assertEqual(self.post(valid, "wrong").status_code, 401)
        self.assertEqual(self.post(self.report(
            publication, "failed", diagnostic="SECRET ******",
        )).status_code, 200)
        self.assertEqual(DHCPResult.objects.get().diagnostic, "runner_reported_error")
        self.assertNotIn("SECRET", self.post(valid).content.decode())

    def test_result_max_size_declared_and_bounded_stream(self):
        publication = self.publish()
        exact = json.dumps(self.report(publication)).encode().ljust(4096, b" ")
        self.assertEqual(self.post(exact).status_code, 200)
        self.assertEqual(self.post(b" " * 4097).status_code, 413)
        request = self.factory.post(
            "/", b" " * 5000, content_type="application/json",
            HTTP_AUTHORIZATION="Bearer " + self.token,
        )
        request.META["CONTENT_LENGTH"] = ""
        self.assertEqual(dhcp_api.result(request, 1).status_code, 413)
        self.assertEqual(self.post(self.report(publication), CONTENT_LENGTH="not-integer").status_code, 400)
        self.assertEqual(DHCPResult.objects.count(), 1)

    def test_duplicates_older_results_and_independent_failure(self):
        old = self.publish()
        self.host.name = "new"
        self.host.save()
        new = self.publish()
        self.assertEqual(self.post(self.report(new)).status_code, 200)
        report = DHCPResult.objects.get()
        self.assertEqual(self.post(self.report(new)).status_code, 200)
        self.assertEqual(DHCPResult.objects.get().received_at, report.received_at)
        self.post(self.report(old))
        self.post(self.report(old, "failed"))
        state = DHCPState.objects.get(site=self.site)
        self.assertEqual(state.applied_id, new.pk)
        self.assertEqual(state.last_attempt.publication_id, new.pk)
        self.assertEqual(state.last_failure.publication_id, old.pk)
        self.post(self.report(new, "failed"))
        self.post(self.report(old, "rejected"))
        state.refresh_from_db()
        self.assertEqual(state.last_failure.publication_id, new.pk)
        self.assertEqual(state.applied_id, new.pk)
        self.assertEqual(state.last_attempt.publication_id, new.pk)
        self.assertFalse(dhcp.status_rows()[0]["pending"])

    def test_other_site_result_version_rejected(self):
        other_token = dhcp.rotate_token(2)
        publication = self.publish()
        request = self.factory.post(
            "/", json.dumps(self.report(publication)), content_type="application/json",
            HTTP_AUTHORIZATION="Bearer " + other_token,
        )
        self.assertEqual(dhcp_api.result(request, 2).status_code, 400)

    def test_bounded_history_pins_and_expired_versions_fail_closed(self):
        pinned = self.publish()
        self.get()
        self.post(self.report(pinned))
        self.post(self.report(pinned, "failed"))
        expired = None
        for index in range(30):
            self.host.name = f"alpha-{index}"
            self.host.save()
            publication = self.publish()
            if expired is None:
                expired = publication
        self.assertLessEqual(DHCPPublication.objects.count(), 25)
        self.assertEqual(DHCPPublication.objects.count(), 21)
        self.assertTrue(DHCPPublication.objects.filter(pk=pinned.pk).exists())
        self.assertFalse(DHCPPublication.objects.filter(pk=expired.pk).exists())
        self.assertEqual(self.post(self.report(expired)).status_code, 400)
        self.assertEqual(self.post(self.report(pinned)).status_code, 200)
        self.assertLessEqual(DHCPResult.objects.count(), 75)


class DHCPMigrationTests(TransactionTestCase):
    def test_additive_migration_preserves_configuration_sites_and_hosts(self):
        executor = MigrationExecutor(connection)
        executor.migrate([("inventory", "0012_host_static")])
        old = executor.loader.project_state([("inventory", "0012_host_static")]).apps
        config = old.get_model("inventory", "Configuration").objects.get(pk=1)
        config.revision = 17
        config.save()
        site = old.get_model("inventory", "Site").objects.get(pk=1)
        site.dsm_ifname = "bond0"
        site.save()
        host = old.get_model("inventory", "Host").objects.create(
            name="preserved", site_id=1, row=1, column=0, static=True,
        )
        try:
            executor = MigrationExecutor(connection)
            executor.migrate([("inventory", "0013_dhcp_publications")])
            self.assertEqual(Configuration.load().revision, 17)
            self.assertEqual(Site.objects.get(pk=1).dsm_ifname, "bond0")
            self.assertTrue(Host.objects.get(pk=host.pk).static)
            self.assertEqual(DHCPPublication.objects.count(), 0)
            self.assertEqual(DHCPState.objects.count(), 0)
        finally:
            MigrationExecutor(connection).migrate([("inventory", "0013_dhcp_publications")])
