import copy
import json
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.core.files.uploadedfile import SimpleUploadedFile
from django.db import connection
from django.test import Client, TestCase, override_settings
from django.test.utils import CaptureQueriesContext
from django.urls import reverse

from .archives import (
    CONFIG_FIELDS, FORMAT, HOST_FIELDS, LEDGER_FIELDS, MAX_BYTES, MAX_ID, MAX_LEDGER,
    diff, dumps, fingerprint, loads, restore, snapshot, validate,
)
from .exporters import build_exports
from .forms import HostForm
from .models import MAX_SERIAL, Configuration, GandiRecord, Host, Site


class ArchiveDataTests(TestCase):
    def setUp(self):
        self.config = Configuration.load()
        self.config.gandi_token = "destination-secret"
        self.config.save(update_fields=["gandi_token"])
        for index, status in enumerate(Host.Status.values, 1):
            Host.objects.create(
                id=10 + index, name=f"host-{index}", site_id=index,
                row=index, column=0, category="hardware metadata", status=status,
                vpn=index != 2, public_export=index == 1,
                mac=f"02:00:00:00:00:0{index}", notes=f"notes {index}",
            )
        GandiRecord.objects.create(
            id=20, zone="example.tld", name="retired.vpn", record_type="A",
            values=["172.28.4.100", "172.28.1.1"], ttl=600,
        )
        self.data = snapshot()

    def test_complete_deterministic_schema_and_secret_exclusion(self):
        self.assertEqual(self.data["format"], FORMAT)
        self.assertEqual(set(self.data["configuration"]), set(CONFIG_FIELDS))
        self.assertEqual(set(self.data["hosts"][0]), set(HOST_FIELDS))
        self.assertEqual(set(self.data["gandi_records"][0]), set(LEDGER_FIELDS))
        self.assertEqual([host["id"] for host in self.data["hosts"]], [11, 12, 13])
        self.assertEqual({host["status"] for host in self.data["hosts"]}, set(Host.Status.values))
        self.assertEqual([site["id"] for site in self.data["sites"]], [1, 2, 3, 4])
        text = dumps(self.data)
        self.assertEqual(text, dumps(snapshot()))
        self.assertEqual(loads(text.encode()), self.data)
        self.assertNotIn("destination-secret", text)
        for field in ("gandi_token", "password", "sessions", "users", "secret_key"):
            self.assertNotIn(f'"{field}"', text)

    def test_format_identifier_is_required_exact_and_strictly_typed(self):
        for value in ("other.application-data", "DNSGRID.application-data", 1, True, None):
            candidate = copy.deepcopy(self.data)
            candidate["format"] = value
            with self.subTest(value=value), self.assertRaises(ValidationError):
                validate(candidate)
        candidate = copy.deepcopy(self.data)
        candidate.pop("format")
        with self.assertRaises(ValidationError):
            validate(candidate)

    def test_snapshot_has_no_write_queries(self):
        with CaptureQueriesContext(connection) as queries:
            snapshot(expected_revision=self.config.revision)
        for query in queries:
            self.assertFalse(query["sql"].lstrip().upper().startswith(("UPDATE", "INSERT", "DELETE")))

    def test_snapshot_rejects_stale_revision(self):
        with self.assertRaises(ValidationError):
            snapshot(expected_revision=self.config.revision + 1)

    def test_schema_and_exact_fields_reject_unknowns_and_missing_values(self):
        mutations = [
            lambda data: data.update(schema_version=2),
            lambda data: data.update(schema_version=True),
            lambda data: data.update(users=[]),
            lambda data: data.pop("sites"),
            lambda data: data["configuration"].update(gandi_token="forbidden"),
            lambda data: data["configuration"].pop("ttl"),
            lambda data: data["hosts"][0].update(unknown=1),
            lambda data: data["sites"][0].update(unknown=1),
            lambda data: data["gandi_records"][0].update(unknown=1),
        ]
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                candidate = copy.deepcopy(self.data)
                mutation(candidate)
                with self.assertRaises(ValidationError):
                    validate(candidate)

    def test_strict_types_are_not_coerced(self):
        cases = [
            ("configuration", "ttl", True), ("configuration", "revision", "2"),
            ("configuration", "lan_domain", 42), ("hosts", "row", False),
            ("hosts", "site_id", "1"), ("hosts", "vpn", 1),
            ("hosts", "notes", None), ("sites", "g", True),
            ("gandi_records", "ttl", 300.0), ("gandi_records", "values", "172.28.1.1"),
        ]
        for section, field, value in cases:
            with self.subTest(section=section, field=field, value=value):
                candidate = copy.deepcopy(self.data)
                target = candidate[section] if section == "configuration" else candidate[section][0]
                target[field] = value
                with self.assertRaises(ValidationError):
                    validate(candidate)

    def test_duplicate_keys_nonfinite_unicode_and_deep_json_rejected(self):
        samples = [
            b'{"schema_version":1,"schema_version":1}',
            dumps(self.data).replace('"revision": 1', '"revision": NaN').encode(),
            b"\xff", b"[", b"[" * 1500 + b"]" * 1500,
            dumps(self.data).replace('"ttl": 300', '"ttl": Infinity').encode(),
        ]
        for sample in samples:
            with self.subTest(sample=sample[:60]):
                with self.assertRaises(ValidationError):
                    loads(sample)

    def test_counts_and_bytes_are_bounded(self):
        with self.assertRaises(ValidationError):
            loads(b" " * (MAX_BYTES + 1))
        for section, size in (("hosts", 128), ("gandi_records", MAX_LEDGER + 1), ("sites", 5)):
            candidate = copy.deepcopy(self.data)
            candidate[section] = [candidate[section][0]] * size
            with self.subTest(section=section), self.assertRaises(ValidationError):
                validate(candidate)

    def test_full_grid_maximum_unicode_notes_export_import_roundtrip(self):
        Host.objects.all().delete()
        notes = "\U0001f600" * 4000
        category = "\U0001f600" * 80
        Host.objects.bulk_create([
            Host(name=f"host-{x}", site_id=x % 4 + 1, row=x % 16, column=x // 16,
                 status=Host.Status.values[x % 3], notes=notes, category=category)
            for x in range(1, 128)
        ])
        exported = snapshot()
        content = dumps(exported).encode("utf-8")
        self.assertGreater(len(content), 6 * 1024 * 1024 - 256 * 1024)
        self.assertLess(len(content), MAX_BYTES)
        self.assertEqual(loads(content), exported)
        self.assertNotIn(b"destination-secret", content)

    def test_host_invariants_and_id_bounds(self):
        cases = [
            ("row", 16), ("row", -1), ("column", 8), ("column", -1),
            ("site_id", 5), ("id", 0), ("id", 2**63), ("name", "bad.label"),
            ("status", "expired"), ("notes", "a" * 4001),
            ("category", "a" * 81), ("mac", "01:00:00:00:00:01"),
            ("notes", "\ud800"), ("notes", "\x00"),
        ]
        for field, value in cases:
            candidate = copy.deepcopy(self.data)
            candidate["hosts"][0][field] = value
            with self.subTest(field=field), self.assertRaises(ValidationError):
                validate(candidate)
        candidate = copy.deepcopy(self.data)
        candidate["hosts"][0].update(row=0, column=0)
        with self.assertRaises(ValidationError):
            validate(candidate)

    def test_incoming_duplicate_hosts_rejected_after_normalization(self):
        for fields in (("id",), ("name",), ("row", "column"), ("mac",)):
            candidate = copy.deepcopy(self.data)
            for field in fields:
                candidate["hosts"][1][field] = candidate["hosts"][0][field]
            with self.subTest(fields=fields), self.assertRaises(ValidationError):
                validate(candidate)
        candidate = copy.deepcopy(self.data)
        candidate["hosts"][1]["name"] = " HOST-1 "
        with self.assertRaises(ValidationError):
            validate(candidate)

    def test_sequence_exhausting_host_and_ledger_ids_are_rejected(self):
        for section in ("hosts", "gandi_records"):
            for pk in (2**63 - 1, 2**63 - 2, MAX_ID + 1, 0, -1):
                candidate = copy.deepcopy(self.data)
                candidate[section][0]["id"] = pk
                with self.subTest(section=section, pk=pk), self.assertRaises(ValidationError):
                    validate(candidate)

    def test_high_supported_restored_ids_preserved_and_autoallocation_still_works(self):
        candidate = copy.deepcopy(self.data)
        candidate["hosts"][0]["id"] = MAX_ID
        candidate["gandi_records"][0]["id"] = MAX_ID
        restore(candidate, expected_revision=1)
        self.assertTrue(Host.objects.filter(pk=MAX_ID, name="host-1").exists())
        self.assertTrue(GandiRecord.objects.filter(pk=MAX_ID, name="retired.vpn").exists())
        following_host = Host.objects.create(
            name="following", site_id=1, row=7, column=2,
        )
        following_record = GandiRecord.objects.create(
            zone="example.tld", name="following.vpn", values=["172.28.1.39"],
        )
        self.assertEqual(following_host.pk, 1)
        self.assertEqual(following_record.pk, 1)
        self.assertEqual(Configuration.load().revision, 2)
        roundtrip = loads(dumps(snapshot()).encode())
        restore(roundtrip, expected_revision=2)
        restored = snapshot()
        restored["configuration"]["revision"] = roundtrip["configuration"]["revision"]
        self.assertEqual(restored, roundtrip)

    def test_deleting_high_restored_rows_does_not_break_later_portable_allocation(self):
        candidate = copy.deepcopy(self.data)
        candidate["hosts"][0]["id"] = MAX_ID
        candidate["gandi_records"][0]["id"] = MAX_ID
        restore(candidate, expected_revision=1)
        Host.objects.filter(pk=MAX_ID).delete()
        GandiRecord.objects.filter(pk=MAX_ID).delete()
        following_host = Host.objects.create(name="later", site_id=1, row=7, column=2)
        following_record = GandiRecord.objects.create(
            zone="example.tld", name="later.vpn", values=["172.28.1.39"],
        )
        self.assertEqual(following_host.pk, 1)
        self.assertEqual(following_record.pk, 1)
        self.assertEqual(Configuration.load().revision, 2)
        portable = snapshot()
        self.assertEqual(loads(dumps(portable).encode()), portable)

    def test_portable_gap_allocation_skips_existing_low_ids_and_updates_normally(self):
        candidate = copy.deepcopy(self.data)
        candidate["hosts"][0]["id"] = MAX_ID
        candidate["hosts"][1]["id"] = 1
        candidate["gandi_records"][0]["id"] = MAX_ID
        restore(candidate, expected_revision=1)
        GandiRecord.objects.create(id=1, zone="example.tld", name="occupied.vpn", values=["172.28.1.10"])
        host = Host.objects.create(name="later", site_id=1, row=7, column=2)
        record = GandiRecord.objects.create(zone="example.tld", name="later.vpn", values=["172.28.1.39"])
        self.assertEqual(host.pk, 2)
        self.assertEqual(record.pk, 2)
        host.notes = "updated without reallocation"
        host.save(update_fields=["notes"])
        record.ttl = 600
        record.save(update_fields=["ttl"])
        self.assertEqual(Host.objects.get(pk=2).notes, host.notes)
        self.assertEqual(GandiRecord.objects.get(pk=2).ttl, 600)
        self.assertEqual(Configuration.load().revision, 2)

    def test_normal_sqlite_autoallocation_retains_monotonic_ids(self):
        original_host_max = Host.objects.order_by("-pk").first().pk
        original_ledger_max = GandiRecord.objects.order_by("-pk").first().pk
        host = Host.objects.create(name="next-host", site_id=1, row=7, column=2)
        record = GandiRecord.objects.create(zone="example.tld", name="next.vpn", values=["172.28.1.39"])
        self.assertEqual(host.pk, original_host_max + 1)
        self.assertEqual(record.pk, original_ledger_max + 1)
        self.assertEqual(Configuration.load().revision, 1)

    def test_fixed_sites_and_distinct_mappings(self):
        cases = [
            lambda data: data["sites"].pop(),
            lambda data: data["sites"][0].update(id=5),
            lambda data: data["sites"][1].update(g=data["sites"][0]["g"]),
            lambda data: data["sites"][1].update(name=data["sites"][0]["name"].upper()),
            lambda data: data["sites"][0].update(g=256),
            lambda data: data["sites"][0].update(name=" "),
        ]
        for mutation in cases:
            candidate = copy.deepcopy(self.data)
            mutation(candidate)
            with self.subTest(mutation=mutation), self.assertRaises(ValidationError):
                validate(candidate)

    def test_candidate_hosts_do_not_conflict_with_outgoing_names_positions_or_macs(self):
        candidate = copy.deepcopy(self.data)
        candidate["hosts"][0]["id"] = 100
        validated = validate(candidate)
        self.assertEqual(validated["hosts"][-1]["id"], 100)

    def test_configuration_dns_length_checks_incoming_not_outgoing_hosts(self):
        long_domain = "a" * 63 + "." + "b" * 63 + "." + "c" * 63 + "." + "d" * 54
        Host.objects.filter(pk=11).update(name="z" * 63)
        candidate = copy.deepcopy(self.data)
        candidate["configuration"]["lan_domain"] = long_domain
        self.assertEqual(validate(candidate)["configuration"]["lan_domain"], long_domain)
        candidate["hosts"][0]["name"] = "z" * 63
        with self.assertRaises(ValidationError):
            validate(candidate)

    def test_host_validation_uses_incoming_not_outgoing_configuration(self):
        domain = "a" * 63 + "." + "b" * 63 + "." + "c" * 63 + "." + "d" * 56
        Configuration.objects.filter(pk=1).update(lan_domain=domain)
        candidate = copy.deepcopy(self.data)
        candidate["hosts"][0]["name"] = "z" * 63
        self.assertEqual(validate(candidate)["hosts"][0]["name"], "z" * 63)

    def test_invalid_configuration_invariants(self):
        for field, value in (
            ("id", 2), ("lan_domain", "localhost"), ("vpn_domain", "vpn.other.tld"),
            ("lan_prefix", "256.1"), ("revision", 0), ("revision", MAX_SERIAL + 1),
            ("ttl", 0), ("ttl", MAX_SERIAL + 1), ("soa_ns", "bad name"),
        ):
            candidate = copy.deepcopy(self.data)
            candidate["configuration"][field] = value
            with self.subTest(field=field), self.assertRaises(ValidationError):
                validate(candidate)

    def test_owned_record_zone_scope_type_ttl_and_values(self):
        for field, value in (
            ("zone", "other.tld"), ("name", "@"), ("name", "outside"),
            ("name", "nested.host.vpn"), ("name", "*.vpn"), ("name", "bad/host.vpn"),
            ("record_type", "CNAME"), ("ttl", 0), ("ttl", MAX_SERIAL + 1),
            ("values", []), ("values", ["::1"]), ("values", ["999.1.1.1"]),
            ("values", [1]), ("values", ["172.28.1.1"] * 2),
            ("values", ["172.28.1.1"] * 17),
        ):
            candidate = copy.deepcopy(self.data)
            candidate["gandi_records"][0][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValidationError):
                validate(candidate)

    def test_ownership_relative_scope_when_vpn_is_zone_apex(self):
        candidate = copy.deepcopy(self.data)
        candidate["configuration"]["vpn_domain"] = "example.tld"
        candidate["gandi_records"][0]["name"] = "old-host"
        self.assertEqual(validate(candidate)["gandi_records"][0]["name"], "old-host")

    def test_duplicate_ownership_ids_and_keys(self):
        for field in ("id", "name"):
            candidate = copy.deepcopy(self.data)
            extra = copy.deepcopy(candidate["gandi_records"][0])
            extra["id"] = 21
            extra["name"] = "another.vpn"
            extra[field] = candidate["gandi_records"][0][field]
            candidate["gandi_records"].append(extra)
            with self.subTest(field=field), self.assertRaises(ValidationError):
                validate(candidate)

    def test_historical_owned_values_are_preserved_for_safe_future_deletion(self):
        self.assertEqual(validate(self.data)["gandi_records"][0]["values"],
                         ["172.28.1.1", "172.28.4.100"])

    def test_restore_complete_ids_metadata_and_exports_users_secrets_preserved(self):
        user = get_user_model().objects.create_user("preserved")
        original_password = user.password
        before_exports = build_exports()
        candidate = copy.deepcopy(self.data)
        candidate["configuration"]["revision"] = 40
        Host.objects.create(name="target-conflict", row=7, column=1, site_id=4)
        result = restore(candidate, expected_revision=1)
        self.assertEqual(result, 41)
        after = snapshot()
        after["configuration"]["revision"] = self.data["configuration"]["revision"]
        self.assertEqual(after, self.data)
        user.refresh_from_db()
        self.assertEqual(user.password, original_password)
        self.assertEqual(Configuration.load().gandi_token, "destination-secret")
        self.assertEqual([host.pk for host in Host.objects.order_by("pk")], [11, 12, 13])
        self.assertEqual(GandiRecord.objects.get().pk, 20)
        for name, artifact in before_exports.items():
            if name != "forward.zone" and not name.startswith("reverse-"):
                self.assertEqual(build_exports()[name], artifact)
            else:
                self.assertEqual(build_exports()[name].replace("\n        41\n", "\n        1\n"), artifact)

    def test_restore_uses_larger_destination_revision(self):
        Configuration.objects.filter(pk=1).update(revision=50)
        self.assertEqual(restore(self.data, expected_revision=50), 51)

    def test_restore_stale_revision_rejected_without_changes(self):
        before = snapshot()
        with self.assertRaises(ValidationError):
            restore(self.data, expected_revision=2)
        self.assertEqual(snapshot(), before)

    def test_restore_overflow_either_source_or_destination_rejected(self):
        for destination, incoming in ((1, MAX_SERIAL), (MAX_SERIAL, 1)):
            Configuration.objects.filter(pk=1).update(revision=destination)
            candidate = copy.deepcopy(self.data)
            candidate["configuration"]["revision"] = incoming
            before = snapshot()
            with self.subTest(destination=destination), self.assertRaises(ValidationError):
                restore(candidate, expected_revision=destination)
            self.assertEqual(snapshot(), before)

    def test_restore_invalid_candidate_rejected_without_writes(self):
        candidate = copy.deepcopy(self.data)
        candidate["hosts"][0]["status"] = "invalid"
        before = snapshot()
        with self.assertRaises(ValidationError):
            restore(candidate, expected_revision=1)
        self.assertEqual(snapshot(), before)

    def test_restore_late_failure_rolls_back_revision_deletes_and_sites(self):
        candidate = copy.deepcopy(self.data)
        candidate["sites"][0]["name"] = "Replacement"
        before = snapshot()
        with patch("inventory.archives.Host.objects.bulk_create", side_effect=RuntimeError("failure")):
            with self.assertRaises(RuntimeError):
                restore(candidate, expected_revision=1)
        self.assertEqual(snapshot(), before)
        self.assertEqual(Configuration.load().gandi_token, "destination-secret")

    def test_changed_target_ledger_rejects_restore_even_without_revision_change(self):
        expected = fingerprint(snapshot())
        GandiRecord.objects.filter(pk=20).update(ttl=100)
        before = snapshot()
        with self.assertRaises(ValidationError):
            restore(self.data, expected_revision=1, expected_fingerprint=expected)
        self.assertEqual(snapshot(), before)

    def test_diff_covers_settings_sites_hosts_and_ownership(self):
        candidate = copy.deepcopy(self.data)
        candidate["configuration"]["ttl"] = 900
        candidate["sites"][0]["name"] = "New site"
        candidate["hosts"][0]["notes"] = "changed"
        candidate["gandi_records"] = []
        labels = {change["label"] for change in diff(self.data, candidate)}
        self.assertTrue({"Setting ttl", "sites ID 1", "hosts ID 11", "gandi_records ID 20"} <= labels)


class MACFormNormalizationTests(TestCase):
    def form(self, mac):
        return HostForm({
            "name": "host", "site": 1, "row": 1, "column": 0,
            "status": "running", "revision": 1, "mac": mac,
        })

    def test_valid_whitespace_before_terminal_semicolon_normalized_before_max_length(self):
        form = self.form(" 00:11:22:33:44:55" + " " * 80 + "; ")
        self.assertTrue(form.is_valid(), form.errors)
        self.assertEqual(form.cleaned_data["mac"], "00:11:22:33:44:55")

    def test_blank_semicolon_and_double_semicolon_rejected_but_empty_mac_allowed(self):
        for value in (";", "  ;  ", "00:11:22:33:44:55;;"):
            form = self.form(value)
            with self.subTest(value=value):
                self.assertFalse(form.is_valid())
                self.assertIn("mac", form.errors)
        self.assertTrue(self.form("").is_valid())


@override_settings(FILE_UPLOAD_MAX_MEMORY_SIZE=MAX_BYTES + 1024)
class ArchiveViewTests(TestCase):
    def setUp(self):
        self.config = Configuration.load()
        self.config.gandi_token = "keep-secret"
        self.config.save(update_fields=["gandi_token"])
        self.user = get_user_model().objects.create_user(username="operator", is_staff=True)
        self.client.force_login(self.user)
        Host.objects.create(name="original", site_id=1, row=1, column=0)
        self.data = snapshot()
        self.data["hosts"][0]["notes"] = "restored note"

    def upload(self, data=None, content=None, revision=1, client=None):
        client = client or self.client
        content = content if content is not None else dumps(data or self.data).encode()
        return client.post(reverse("archive-upload"), {
            "archive": SimpleUploadedFile("archive.json", content, content_type="application/json"),
            "revision": revision,
        })

    def confirm(self, **kwargs):
        pending = self.client.session["pending"]
        data = {"nonce": pending["nonce"], "replace_ack": "yes", "ledger_ack": "yes"}
        data.update(kwargs)
        return self.client.post(reverse("confirm"), data)

    def test_archive_routes_require_staff(self):
        anonymous = Client()
        member = get_user_model().objects.create_user("member")
        client = Client()
        client.force_login(member)
        for name in ("archive-download", "archive-upload"):
            with self.subTest(name=name):
                self.assertEqual(anonymous.get(reverse(name)).status_code, 302)
                self.assertEqual(client.get(reverse(name)).status_code, 403)
                self.assertEqual(client.post(reverse(name)).status_code, 403)

    def test_download_requires_revision_is_noncacheable_and_deterministic(self):
        url = reverse("archive-download")
        self.assertEqual(self.client.get(url).status_code, 400)
        self.assertEqual(self.client.get(url, {"revision": "2"}).status_code, 409)
        self.assertEqual(self.client.get(url, {"revision": "1" * 100}).status_code, 400)
        response = self.client.get(url, {"revision": 1})
        self.assertEqual(response.status_code, 200)
        self.assertIn("no-store", response["Cache-Control"])
        self.assertIn("dnsgrid-archive-v1.json", response["Content-Disposition"])
        self.assertEqual(json.loads(response.content), snapshot())
        self.assertNotIn(b"keep-secret", response.content)
        self.assertEqual(self.client.get(url, {"revision": 1}).content, response.content)

    def test_export_page_links_revision_bound_archive_and_restore(self):
        response = self.client.get(reverse("exports"))
        self.assertContains(response, f'<form method="get" action="{reverse("archive-download")}">')
        self.assertContains(response, '<input type="hidden" name="revision" value="1">', html=True)
        self.assertContains(response, "<button>Download complete application-data archive (JSON v1)</button>", html=True)
        self.assertContains(response, reverse("archive-upload"))
        self.assertContains(self.client.get(reverse("configuration")), reverse("archive-upload"))

    def test_settings_has_explicit_multipart_csrf_upload_with_current_revision_and_warnings(self):
        Configuration.objects.filter(pk=1).update(revision=7)
        response = self.client.get(reverse("configuration"))
        self.assertContains(response, "Import application-data archive")
        self.assertContains(response, f'<form method="post" enctype="multipart/form-data" action="{reverse("archive-upload")}" class="editor">')
        self.assertContains(response, 'type="file" name="archive"')
        self.assertEqual(response.context["archive_form"].initial["revision"], 7)
        self.assertContains(response, 'name="csrfmiddlewaretoken"')
        for text in ("Preview archive replacement", "Destructive replacement",
                     "not a SQLite database backup", "SAME Gandi domain",
                     "pending confirmations", "No automatic DNS/DHCP/Gandi deployment"):
            self.assertContains(response, text)

    def test_upload_get_form_warns_about_scope_secrets_and_writer(self):
        response = self.client.get(reverse("archive-upload"))
        self.assertContains(response, 'enctype="multipart/form-data"')
        self.assertContains(response, "SAME Gandi domain")
        self.assertContains(response, "simultaneous Gandi writers")
        self.assertContains(response, "excluded")
        self.assertContains(response, "No automatic DNS/DHCP/Gandi deployment")
        self.assertContains(response, "pending confirmations")
        self.assertIn("no-store", response["Cache-Control"])

    def test_preview_read_only_diff_nonce_warnings_and_explicit_acknowledgments(self):
        before = snapshot()
        with patch("inventory.gandi.GandiClient", side_effect=AssertionError("No API allowed")):
            response = self.upload()
        self.assertEqual(snapshot(), before)
        self.assertContains(response, "restored note")
        self.assertContains(response, 'name="replace_ack"')
        self.assertContains(response, 'name="ledger_ack"')
        self.assertContains(response, "Resulting SOA serial")
        self.assertNotContains(response, "keep-secret")
        pending = self.client.session["pending"]
        self.assertEqual(pending["kind"], "archive")
        self.assertEqual(pending["revision"], 1)
        self.assertEqual(len(pending["nonce"]), 32)
        self.assertLess(len(json.dumps(pending)), MAX_BYTES + 1024)

    def test_restore_confirmation_changes_only_application_data_and_never_calls_provider(self):
        self.upload()
        with patch("inventory.gandi.GandiClient", side_effect=AssertionError("No API allowed")):
            self.assertEqual(self.confirm().status_code, 302)
        self.assertEqual(Host.objects.get().notes, "restored note")
        self.assertEqual(Configuration.load().revision, 2)
        self.assertEqual(Configuration.load().gandi_token, "keep-secret")
        self.assertTrue(get_user_model().objects.filter(pk=self.user.pk).exists())
        self.assertNotIn("pending", self.client.session)

    def test_each_confirmation_acknowledgment_is_required(self):
        for field in ("replace_ack", "ledger_ack"):
            before = snapshot()
            self.upload()
            self.confirm(**{field: ""})
            self.assertEqual(snapshot(), before)
            self.assertNotIn("pending", self.client.session)

    def test_stale_confirmation_clears_pending_without_restore(self):
        self.upload()
        Configuration.objects.filter(pk=1).update(revision=2)
        before = snapshot()
        self.confirm()
        self.assertEqual(snapshot(), before)
        self.assertNotIn("pending", self.client.session)

    def test_ownership_change_after_preview_clears_pending_without_restore(self):
        self.upload()
        GandiRecord.objects.create(zone="example.tld", name="retired.vpn", values=["172.28.1.1"])
        before = snapshot()
        self.confirm()
        self.assertEqual(snapshot(), before)
        self.assertNotIn("pending", self.client.session)

    def test_nonce_replay_and_wrong_nonce_clear_pending(self):
        self.upload()
        nonce = self.client.session["pending"]["nonce"]
        self.confirm(nonce="wrong")
        self.assertNotIn("pending", self.client.session)
        self.assertEqual(Configuration.load().revision, 1)
        self.upload()
        self.confirm()
        before = snapshot()
        self.client.post(reverse("confirm"), {"nonce": nonce, "replace_ack": "yes", "ledger_ack": "yes"})
        self.assertEqual(snapshot(), before)

    def test_cancel_requires_post_clears_session_and_has_no_inventory_effect(self):
        self.upload()
        before = snapshot()
        self.assertEqual(self.client.get(reverse("cancel")).status_code, 405)
        self.assertIn("pending", self.client.session)
        self.assertEqual(self.client.post(reverse("cancel")).status_code, 302)
        self.assertNotIn("pending", self.client.session)
        self.assertEqual(snapshot(), before)

    def test_invalid_and_oversize_uploads_clear_old_pending(self):
        for content in (b'{"bad":1}', b" " * (MAX_BYTES + 1)):
            self.upload()
            before = snapshot()
            response = self.upload(content=content)
            self.assertEqual(response.status_code, 200)
            self.assertTrue(response.context["form"].errors)
            self.assertEqual(snapshot(), before)
            self.assertNotIn("pending", self.client.session)

    def test_stale_upload_and_exhausted_serial_have_no_pending(self):
        for revision, incoming in ((2, 1), (1, MAX_SERIAL)):
            candidate = copy.deepcopy(self.data)
            candidate["configuration"]["revision"] = incoming
            response = self.upload(candidate, revision=revision)
            self.assertTrue(response.context["form"].errors)
            self.assertNotIn("pending", self.client.session)
            self.assertEqual(Configuration.load().revision, 1)

    def test_upload_confirm_cancel_csrf_required(self):
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.user)
        self.assertEqual(self.upload(client=client).status_code, 403)
        self.upload()
        for name in ("confirm", "cancel"):
            self.assertEqual(client.post(reverse(name)).status_code, 403)
        self.assertEqual(Configuration.load().revision, 1)

    def test_new_preview_invalidates_previous_nonce(self):
        self.upload()
        nonce = self.client.session["pending"]["nonce"]
        self.upload()
        self.assertNotEqual(nonce, self.client.session["pending"]["nonce"])
        self.confirm(nonce=nonce)
        self.assertEqual(Configuration.load().revision, 1)
        self.assertNotIn("pending", self.client.session)
