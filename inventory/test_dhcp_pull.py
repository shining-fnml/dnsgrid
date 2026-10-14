import copy
import http.client
import io
import json
import os
from pathlib import Path
import ssl
import subprocess
import sys
import tempfile
import urllib.error
import uuid
from unittest.mock import patch

from django.test import SimpleTestCase

from synology import dhcp_pull as pull, dsm_apply


def payload(count=2, offset=0):
    return {"ifname": "eth0", "reservationData": [
        {"mac": f"02:00:00:00:00:{index + offset:02x}",
         "ip": f"192.168.1.{index + offset}", "hostname": f"host-{index + offset}"}
        for index in range(1, count + 1)
    ]}


def envelope(count=2, version="v1", authorized=False, offset=0):
    value = {
        "schema_version": 1, "site_id": 7, "subnet": "192.168.1.0/24",
        "version": version, "sha256": "", "published_at": "2026-10-14T00:00:00Z",
        "destructive_authorized": authorized, "payload": payload(count, offset),
    }
    value["sha256"] = pull.digest(value["payload"])
    return value


class FakeDSM:
    def __init__(self, live):
        self.live = copy.deepcopy(live)
        self.calls = []
        self.fail_set = False
        self.fail_read = False
        self.wrong_verification = False
        self.set_then_fail = False

    @staticmethod
    def response(value):
        return {"success": True, "data": {"reservationList": {
            "ipv4": [{"clid": item["mac"], "ip": item["ip"], "hostname": item["hostname"]}
                     for item in value["reservationData"]], "ipv6": [],
        }}}

    def __call__(self, method, ifname, reservations=None, **kwargs):
        self.calls.append(method)
        assert ifname == "eth0"
        assert kwargs["max_output"] == pull.MAX_BODY
        if method == "get":
            if self.fail_read:
                raise subprocess.TimeoutExpired("private-output", 120)
            return self.response(self.live)
        if self.fail_set:
            raise ValueError("private-output")
        if not self.wrong_verification:
            self.live = {"ifname": ifname, "reservationData": copy.deepcopy(reservations)}
        if self.set_then_fail:
            raise subprocess.TimeoutExpired("private-output", 120)
        return {"success": True}


class FakeTransport:
    def __init__(self, current=None):
        self.current = current or envelope()
        self.gets = []
        self.posts = []
        self.fail_post = False
        self.fail_get = False
        self.not_modified = False
        self.raw = None
        self.tag = None
        self.post_body = None

    def request(self, method, resource, body=None, conditional=None):
        if method == "GET":
            self.gets.append(conditional)
            if self.fail_get:
                raise pull.SafeError("network_failed")
            if self.not_modified:
                return 304, conditional, b""
            return 200, self.tag or pull.etag(self.current), \
                self.raw if self.raw is not None else json.dumps(self.current).encode()
        self.posts.append(copy.deepcopy(body))
        if self.fail_post:
            raise pull.SafeError("network_failed")
        return 200, None, self.post_body if self.post_body is not None else \
            json.dumps({"status": body["status"]}).encode("ascii")


class PullTests(SimpleTestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix=".dhcp-tests-", dir=Path.cwd())
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.config = {
            "base_url": "https://example.invalid/prefix", "site_id": 7, "ifname": "eth0",
            "subnet": "192.168.1.0/24", "token": "test-only-not-a-credential",
            "timeout": 3, "state_dir": self.root / "state",
        }
        self.transport = FakeTransport()
        self.dsm = FakeDSM(payload(2, 10))
        self.addCleanup(patch.stopall)
        patch("synology.dhcp_pull.Transport", return_value=self.transport).start()
        patch("synology.dsm_apply.call_api", side_effect=self.dsm).start()

    def run_pull(self, reconcile=False):
        return pull.run(self.config, reconcile)

    def state(self):
        return json.loads((self.config["state_dir"] / "state.json").read_text())

    def install_state(self, **values):
        with pull.Store(self.config) as store:
            state = pull.empty_state(self.config)
            state.update(values)
            store.save(state)

    def test_first_apply_backup_verify_durable_state(self):
        self.assertEqual(self.run_pull(), 0)
        self.assertEqual(self.dsm.calls, ["get", "get", "set", "get"])
        state = self.state()
        self.assertEqual(state["fetched"], self.transport.current)
        self.assertEqual(state["applied"], self.transport.current)
        self.assertIsNone(state["inflight"])
        self.assertIsNone(state["pending"])
        self.assertEqual(self.transport.posts, [pull.acknowledgement(
            self.transport.current, "applied", report_id=self.transport.posts[0]["report_id"],
        )])
        backup, = (self.config["state_dir"] / "backups").glob("dsm-*")
        self.assertEqual(json.loads((backup / "reservations.json").read_text()), payload(2, 10))
        self.assertEqual(backup.stat().st_mode & 0o777, 0o700)
        self.assertEqual((backup / "reservations.json").stat().st_mode & 0o777, 0o600)
        self.assertEqual((self.config["state_dir"] / "state.json").stat().st_mode & 0o777, 0o600)

    def test_applied_report_only_after_verified_durable_state(self):
        original = self.transport.request

        def request(method, *args, **kwargs):
            if method == "POST":
                state = self.state()
                self.assertTrue(pull.equal(self.dsm.live, state["applied"]["payload"]))
                self.assertEqual(state["pending"], pull.acknowledgement(
                    state["applied"], "applied", report_id=state["pending"]["report_id"],
                ))
                self.assertIsNone(state["inflight"])
            return original(method, *args, **kwargs)

        self.transport.request = request
        self.assertEqual(self.run_pull(), 0)

    def test_identical_first_publication_needs_live_read_but_no_set(self):
        self.dsm.live = self.transport.current["payload"]
        self.assertEqual(self.run_pull(), 0)
        self.assertEqual(self.dsm.calls, ["get"])
        self.assertFalse((self.config["state_dir"] / "backups").exists())

    def test_changed_publication_and_semantic_noop(self):
        self.assertEqual(self.run_pull(), 0)
        self.transport.current = envelope(version="v2", offset=20)
        self.assertEqual(self.run_pull(), 0)
        self.assertEqual(self.transport.gets, [None, '"v1"'])
        self.assertEqual(self.dsm.calls.count("set"), 2)
        self.transport.current = envelope(version="v3", offset=20)
        self.transport.current["payload"]["reservationData"].reverse()
        self.transport.current["sha256"] = pull.digest(self.transport.current["payload"])
        self.assertEqual(self.run_pull(), 0)
        self.assertEqual(self.dsm.calls.count("set"), 2)
        self.assertEqual(self.state()["applied"]["version"], "v3")

    def test_304_reads_live_without_write(self):
        self.run_pull()
        self.transport.not_modified = True
        self.dsm.calls.clear()
        self.assertEqual(self.run_pull(), 0)
        self.assertEqual(self.dsm.calls, ["get"])
        self.assertEqual(self.transport.gets[-1], '"v1"')

    def test_unexpected_304_is_not_trusted(self):
        self.transport.not_modified = True
        with self.assertRaises(pull.SafeError):
            self.run_pull()
        self.assertEqual(self.dsm.calls, [])

    def test_bad_fetch_and_schema_do_not_write_or_report(self):
        self.transport.fail_get = True
        with self.assertRaises(pull.SafeError):
            self.run_pull()
        self.transport.fail_get = False
        for body in (b"broken", b'{"schema_version":1,"schema_version":1}', b"null", b"[]"):
            self.transport.raw = body
            with self.subTest(body=body), self.assertRaises(pull.SafeError):
                self.run_pull()
        self.assertEqual(self.dsm.calls, [])
        self.assertEqual(self.transport.posts, [])

    def test_invalid_etag_prevents_live_read_or_write(self):
        self.transport.tag = '"other"'
        with self.assertRaises(pull.SafeError):
            self.run_pull()
        self.assertEqual(self.dsm.calls, [])

    def test_wrong_interface_and_schema_fail_before_any_dsm_operation(self):
        wrong_interface = envelope()
        wrong_interface["payload"]["ifname"] = "bond0"
        wrong_interface["sha256"] = pull.digest(wrong_interface["payload"])
        wrong_schema = envelope()
        wrong_schema["schema_version"] = True
        self.transport.current = wrong_interface
        self.assertEqual(self.run_pull(), 2)
        self.assertEqual(self.transport.posts[-1], pull.acknowledgement(
            wrong_interface, "rejected", "mapping_mismatch",
            report_id=self.transport.posts[-1]["report_id"],
        ))
        self.assertIsNone(self.state()["fetched"])
        self.transport.posts.clear()
        self.transport.current = wrong_schema
        with self.assertRaises(pull.SafeError):
            self.run_pull()
        self.assertEqual(self.dsm.calls, [])
        self.assertEqual(self.transport.posts, [])

    def test_trustworthy_wrong_subnet_reports_rejection_and_retries(self):
        self.transport.current["subnet"] = "192.168.2.0/24"
        for item in self.transport.current["payload"]["reservationData"]:
            item["ip"] = item["ip"].replace("192.168.1.", "192.168.2.")
        self.transport.current["sha256"] = pull.digest(self.transport.current["payload"])
        self.transport.fail_post = True
        self.assertEqual(self.run_pull(), 2)
        self.assertEqual(self.state()["pending"]["diagnostic"], "mapping_mismatch")
        self.assertIsNone(self.state()["fetched"])
        self.transport.fail_post = False
        self.assertEqual(self.run_pull(), 2)
        self.assertIsNone(self.state()["pending"])
        self.assertEqual(self.dsm.calls, [])

    def test_empty_requires_exact_envelope_authorization(self):
        self.transport.current = envelope(0)
        self.assertEqual(self.run_pull(), 2)
        self.assertEqual(self.dsm.calls, ["get"])
        self.assertIsNone(self.state()["applied"])
        self.assertEqual(self.transport.posts[-1]["diagnostic"], "destructive_not_authorized")
        self.transport.current = envelope(0, version="v2", authorized=True)
        self.assertEqual(self.run_pull(), 0)
        self.assertEqual(self.dsm.live["reservationData"], [])

    def test_empty_even_empty_baseline_requires_authorization(self):
        self.dsm.live = payload(0)
        self.transport.current = envelope(0)
        self.assertEqual(self.run_pull(), 2)
        self.assertNotIn("set", self.dsm.calls)

    def test_half_live_threshold_boundary_and_previous_applied_count(self):
        self.dsm.live = payload(4, 10)
        self.assertEqual(self.run_pull(), 0)
        self.transport.current = envelope(1, version="v2")
        self.assertEqual(self.run_pull(), 0)  # Exactly half is allowed.
        self.transport.current = envelope(0, version="v3", authorized=True)
        self.assertEqual(self.run_pull(), 0)
        self.dsm.live = payload(8, 10)
        self.transport.current = envelope(3, version="v4")
        self.assertEqual(self.run_pull(True), 2)
        # Previous applied baseline is enforced even if DSM drift shrank live.
        self.install_state(applied=envelope(8), fetched=envelope(8))
        self.dsm.live = payload(2)
        self.transport.current = envelope(3, version="v5")
        self.assertEqual(self.run_pull(True), 2)

    def test_external_drift_including_304_requires_reconciliation(self):
        self.run_pull()
        self.transport.not_modified = True
        self.dsm.live = payload(2, 30)
        count = self.dsm.calls.count("set")
        self.assertEqual(self.run_pull(), 2)
        self.assertEqual(self.dsm.calls.count("set"), count)
        self.assertEqual(self.transport.posts[-1]["diagnostic"], "dsm_drift")
        self.assertEqual(self.run_pull(True), 0)
        self.assertEqual(self.dsm.calls.count("set"), count + 1)

    def test_repeated_drift_reconciliation_reports_each_status_transition(self):
        self.assertEqual(self.run_pull(), 0)
        self.transport.not_modified = True
        for _ in range(2):
            self.dsm.live = payload(2, 30)
            self.assertEqual(self.run_pull(), 2)
            self.assertEqual(self.run_pull(True), 0)
        self.dsm.live = payload(2, 30)
        self.assertEqual(self.run_pull(), 2)
        self.assertEqual(
            [report["status"] for report in self.transport.posts],
            ["applied", "rejected", "applied", "rejected", "applied", "rejected"],
        )
        self.assertEqual({report["version"] for report in self.transport.posts}, {"v1"})
        identifiers = [report["report_id"] for report in self.transport.posts]
        self.assertEqual(len(set(identifiers)), len(identifiers))
        for identifier in identifiers:
            self.assertEqual(str(uuid.UUID(identifier)), identifier)
        self.assertEqual(self.state()["fetched"]["version"], "v1")
        self.assertEqual(self.state()["applied"]["version"], "v1")

    def test_reconciliation_still_requires_destructive_authorization(self):
        self.run_pull()
        self.dsm.live = payload(8, 20)
        self.transport.current = envelope(1, version="v2")
        self.assertEqual(self.run_pull(True), 2)
        self.transport.current = envelope(1, version="v3", authorized=True)
        self.assertEqual(self.run_pull(True), 0)

    def test_read_failure_and_timeout_report_fixed_failure(self):
        self.dsm.fail_read = True
        self.assertEqual(self.run_pull(), 1)
        self.assertEqual(self.dsm.calls, ["get"])
        self.assertIsNone(self.state()["applied"])
        self.assertEqual(self.transport.posts[-1]["diagnostic"], "dsm_failed")
        self.assertNotIn("private-output", json.dumps(self.transport.posts))

    def test_read_failure_then_verified_noop_reports_fresh_success(self):
        self.assertEqual(self.run_pull(), 0)
        count = self.dsm.calls.count("set")
        self.dsm.fail_read = True
        self.assertEqual(self.run_pull(), 1)
        failed_id = self.transport.posts[-1]["report_id"]
        self.assertEqual(self.state()["last_report"]["status"], "failed")
        self.dsm.fail_read = False
        self.transport.not_modified = True
        self.assertEqual(self.run_pull(), 0)
        self.assertEqual(self.transport.posts[-1]["status"], "applied")
        self.assertNotEqual(self.transport.posts[-1]["report_id"], failed_id)
        self.assertEqual(self.dsm.calls.count("set"), count)
        reports = len(self.transport.posts)
        self.assertEqual(self.run_pull(), 0)
        self.assertEqual(len(self.transport.posts), reports)

    def test_manually_restored_drift_reconcile_reports_success_without_set(self):
        self.assertEqual(self.run_pull(), 0)
        count = self.dsm.calls.count("set")
        self.transport.not_modified = True
        self.dsm.live = payload(2, 30)
        self.assertEqual(self.run_pull(), 2)
        rejected_id = self.transport.posts[-1]["report_id"]
        self.assertEqual(self.state()["last_report"]["status"], "rejected")
        self.dsm.live = self.transport.current["payload"]
        self.assertEqual(self.run_pull(True), 0)
        self.assertEqual(self.transport.posts[-1]["status"], "applied")
        self.assertNotEqual(self.transport.posts[-1]["report_id"], rejected_id)
        self.assertEqual(self.dsm.calls.count("set"), count)

    def test_set_failure_does_not_advance_etag_and_unchanged_baseline_retries(self):
        self.dsm.fail_set = True
        self.assertEqual(self.run_pull(), 1)
        self.assertIsNone(self.state()["applied"])
        self.assertEqual(self.state()["inflight"], self.transport.current)
        self.dsm.fail_set = False
        count = self.dsm.calls.count("set")
        self.assertEqual(self.run_pull(), 0)
        self.assertEqual(self.transport.gets[-1], None)
        self.assertEqual(self.dsm.calls.count("set"), count + 1)
        self.assertFalse(self.state()["blocked"])
        self.assertIsNone(self.state()["baseline"])

    def test_failed_write_unknown_partial_state_requires_reconciliation(self):
        self.dsm.fail_set = True
        self.assertEqual(self.run_pull(), 1)
        self.dsm.fail_set = False
        self.dsm.live = payload(2, 30)
        count = self.dsm.calls.count("set")
        self.assertEqual(self.run_pull(), 2)
        self.assertEqual(self.dsm.calls.count("set"), count)
        self.assertTrue(self.state()["blocked"])
        self.assertEqual(self.run_pull(True), 0)

    def test_unchanged_baseline_recovery_preserves_pending_failure_event(self):
        self.dsm.wrong_verification = True
        self.transport.fail_post = True
        self.assertEqual(self.run_pull(), 1)
        failed = copy.deepcopy(self.state()["pending"])
        self.assertEqual(failed["diagnostic"], "verification_failed")
        self.dsm.wrong_verification = False
        self.transport.fail_post = False
        self.assertEqual(self.run_pull(), 0)
        self.assertEqual(self.transport.posts[:2], [failed, failed])
        self.assertEqual(self.transport.posts[-1]["status"], "applied")
        self.assertNotEqual(self.transport.posts[-1]["report_id"], failed["report_id"])

    def test_delivered_failure_not_reported_again_during_baseline_retry(self):
        self.dsm.fail_set = True
        self.assertEqual(self.run_pull(), 1)
        self.assertIsNone(self.state()["pending"])
        self.dsm.fail_set = False
        self.assertEqual(self.run_pull(), 0)
        self.assertEqual([report["status"] for report in self.transport.posts], ["failed", "applied"])

    def test_verification_failure_keeps_applied_version(self):
        self.run_pull()
        original = self.state()["applied"]
        self.transport.current = envelope(version="v2", offset=20)
        self.dsm.wrong_verification = True
        self.assertEqual(self.run_pull(), 1)
        self.assertEqual(self.state()["applied"], original)
        self.assertEqual(self.transport.posts[-1]["diagnostic"], "verification_failed")

    def test_ack_failure_retains_applied_and_retries_without_apply(self):
        self.transport.fail_post = True
        self.assertEqual(self.run_pull(), 1)
        state = self.state()
        self.assertEqual(state["applied"], self.transport.current)
        self.assertEqual(state["pending"]["status"], "applied")
        pending = copy.deepcopy(state["pending"])
        self.transport.fail_post = False
        self.transport.not_modified = True
        count = self.dsm.calls.count("set")
        self.assertEqual(self.run_pull(), 0)
        self.assertEqual(self.dsm.calls.count("set"), count)
        self.assertIsNone(self.state()["pending"])
        self.assertEqual(self.transport.posts, [pending, pending])

    def test_malformed_or_mismatched_success_receipt_retains_pending(self):
        for body in (b"<html>proxy login</html>", b"{", b'{"status":"failed"}',
                     b'{"status":"applied","status":"applied"}', b'{"status":"applied","extra":true}'):
            self.transport.post_body = body
            self.assertEqual(self.run_pull(), 1)
            pending = copy.deepcopy(self.state()["pending"])
            self.assertEqual(pending["status"], "applied")
            self.assertIsNone(self.state()["last_report"])
            sets = self.dsm.calls.count("set")
            self.assertEqual(self.run_pull(), 1)
            self.assertEqual(self.state()["pending"], pending)
            self.assertEqual(self.dsm.calls.count("set"), sets)
            self.transport.post_body = None
            self.assertEqual(self.run_pull(), 0)
            self.assertIsNone(self.state()["pending"])
            # Reset only test fixture state for the next independently malformed receipt.
            self.install_state()
            self.dsm.live = payload(2, 10)

    def test_failure_reports_preserve_uuid_until_retry_is_delivered(self):
        self.dsm.fail_read = True
        self.transport.fail_post = True
        self.assertEqual(self.run_pull(), 1)
        pending = self.state()["pending"]
        self.assertEqual(self.run_pull(), 1)
        self.assertEqual(self.state()["pending"], pending)
        self.assertEqual(self.transport.posts, [pending, pending])
        self.transport.fail_post = False
        self.assertEqual(self.run_pull(), 1)
        self.assertEqual(self.transport.posts[-1], pending)

    def test_legacy_pending_without_report_id_remains_retryable(self):
        published = envelope()
        legacy = pull.acknowledgement(published, "applied", report_id=None)
        self.install_state(applied=published, fetched=published, pending=legacy)
        old_state = self.state()
        del old_state["last_report"]
        (self.config["state_dir"] / "state.json").write_text(json.dumps(old_state))
        self.dsm.live = published["payload"]
        self.transport.not_modified = True
        self.assertEqual(self.run_pull(), 0)
        self.assertEqual(self.transport.posts, [legacy])

    def test_invalid_or_noncanonical_report_id_state_is_rejected(self):
        published = envelope()
        for report_id in ("not-a-uuid", str(uuid.uuid4()).upper(), "0" * 32, str(uuid.UUID(int=0))):
            state = pull.empty_state(self.config)
            state.update(applied=published, fetched=published,
                         pending=pull.acknowledgement(published, "applied", report_id=report_id))
            with self.subTest(report_id=report_id), self.assertRaises(pull.SafeError):
                pull.validate_state(state, self.config)

    def test_operator_reconcile_never_retires_undeliverable_older_report(self):
        original = envelope()
        old_ack = pull.acknowledgement(original, "applied")
        self.install_state(applied=original, fetched=original, pending=old_ack)
        self.dsm.live = original["payload"]
        self.transport.current = envelope(version="v2")
        request = self.transport.request

        def reject_old(method, resource, body=None, **kwargs):
            if method == "POST" and body["version"] == "v1":
                raise pull.SafeError("http_failed")
            return request(method, resource, body, **kwargs)

        self.transport.request = reject_old
        self.assertEqual(self.run_pull(), 1)
        self.assertEqual(self.state()["pending"], old_ack)
        self.assertEqual(self.run_pull(True), 1)
        self.assertEqual(self.state()["applied"]["version"], "v1")
        self.assertEqual(self.state()["pending"], old_ack)
        self.assertNotIn("set", self.dsm.calls)
        self.assertEqual(self.transport.posts, [])

    def test_operator_reconcile_never_retires_same_version_pending_report(self):
        current = envelope()
        pending = pull.acknowledgement(current, "applied")
        self.install_state(applied=current, fetched=current, pending=pending)
        self.dsm.live = current["payload"]
        self.transport.fail_post = True
        self.assertEqual(self.run_pull(True), 1)
        self.assertEqual(self.state()["pending"], pending)
        self.assertNotIn("set", self.dsm.calls)

    def test_drift_never_retries_false_applied_ack_even_with_reconcile(self):
        for reconcile in (False, True):
            self.install_state(
                applied=envelope(), fetched=envelope(),
                pending=pull.acknowledgement(envelope(), "applied"),
            )
            self.dsm.live = payload(2, 30)
            self.transport.posts.clear()
            self.assertEqual(self.run_pull(reconcile), 0 if reconcile else 2)
            self.assertEqual(self.transport.posts[0]["status"], "rejected")
            self.assertEqual(self.transport.posts[0]["diagnostic"], "dsm_drift")
            if reconcile:
                self.assertEqual(self.transport.posts[-1]["status"], "applied")

    def test_undelivered_rejection_retained_during_newer_drift(self):
        applied = envelope()
        rejected = envelope(version="v2", offset=20)
        self.install_state(
            applied=applied, fetched=rejected,
            pending=pull.acknowledgement(rejected, "rejected", "dsm_drift"),
        )
        self.dsm.live = payload(2, 30)
        self.transport.current = envelope(version="v3", offset=40)
        self.transport.fail_post = True
        self.assertEqual(self.run_pull(), 1)
        self.assertEqual(self.state()["pending"]["version"], "v2")
        self.assertEqual(self.state()["fetched"]["version"], "v2")
        self.assertNotIn("set", self.dsm.calls)

    def test_rejected_report_retry_and_failed_etag_never_advance(self):
        self.transport.current = envelope(0)
        self.transport.fail_post = True
        self.assertEqual(self.run_pull(), 2)
        self.assertEqual(self.state()["pending"]["status"], "rejected")
        self.transport.fail_post = False
        self.assertEqual(self.run_pull(), 2)
        self.assertEqual(self.transport.gets, [None, None])
        self.assertIsNone(self.state()["pending"])
        self.assertNotIn("set", self.dsm.calls)

    def test_crash_after_set_recovers_verified_attempt_without_second_set(self):
        self.dsm.set_then_fail = True
        self.transport.fail_post = True
        self.assertEqual(self.run_pull(), 1)
        self.assertIsNotNone(self.state()["inflight"])
        self.dsm.set_then_fail = False
        self.transport.fail_post = False
        count = self.dsm.calls.count("set")
        self.assertEqual(self.run_pull(), 0)
        self.assertEqual(self.dsm.calls.count("set"), count)
        self.assertEqual(self.state()["applied"], self.transport.current)
        self.assertIsNone(self.state()["inflight"])
        self.assertEqual(self.transport.posts[-1]["status"], "applied")

    def test_recovery_with_newer_publication_and_failed_prior_attempt(self):
        self.install_state(fetched=envelope(), inflight=envelope(), baseline=payload(2, 40))
        self.transport.current = envelope(version="v2", offset=20)
        self.assertEqual(self.run_pull(), 2)
        self.assertEqual(self.state()["fetched"]["version"], "v2")
        self.assertNotIn("set", self.dsm.calls)
        self.assertEqual(self.run_pull(True), 0)

    def test_persistence_failure_before_write_prevents_set_and_ack(self):
        with patch.object(pull.Store, "save", side_effect=OSError("private-output")):
            with self.assertRaises(pull.SafeError):
                self.run_pull()
        self.assertNotIn("set", self.dsm.calls)
        self.assertEqual(self.transport.posts, [])

    def test_persistence_failure_after_set_has_no_applied_report_and_recovers(self):
        original = pull.Store.save

        def save(store, state):
            if state["applied"] is not None:
                raise OSError("private-output")
            original(store, state)

        with patch.object(pull.Store, "save", save):
            with self.assertRaises(OSError):
                self.run_pull()
        self.assertEqual(self.transport.posts, [])
        self.assertIsNone(self.state()["applied"])
        self.assertIsNotNone(self.state()["inflight"])
        self.assertEqual(self.run_pull(), 0)
        self.assertEqual(self.dsm.calls.count("set"), 1)

    def test_backup_failure_and_stale_baseline_prevent_set(self):
        with patch("synology.dsm_apply.backup_reservations", side_effect=OSError("private-output")):
            with self.assertRaises(pull.SafeError):
                self.run_pull()
        self.assertNotIn("set", self.dsm.calls)
        self.dsm.calls.clear()
        original = self.dsm.__call__

        def api(*args, **kwargs):
            if self.dsm.calls:
                self.dsm.live = payload(3, 30)
            return original(*args, **kwargs)

        with patch("synology.dsm_apply.call_api", side_effect=api):
            self.assertEqual(self.run_pull(), 2)
        self.assertNotIn("set", self.dsm.calls)
        self.assertEqual(self.transport.posts[-1]["diagnostic"], "baseline_changed")

    def test_lock_prevents_all_requests(self):
        with pull.Store(self.config):
            with self.assertRaises(pull.SafeError) as error:
                self.run_pull()
            self.assertEqual(error.exception.code, "already_running")
        self.assertEqual(self.transport.gets, [])

    def test_unsafe_state_directory_leaf_files_and_ancestors_fail_closed(self):
        path = self.config["state_dir"]
        path.mkdir(mode=0o755)
        with self.assertRaises(pull.SafeError):
            self.run_pull()
        path.chmod(0o700)
        (path / "state.json").symlink_to(self.root / "missing")
        with self.assertRaises(OSError):
            self.run_pull()
        (path / "state.json").unlink()
        (path / "lock").unlink()
        (path / "lock").symlink_to(self.root / "missing")
        with self.assertRaises(OSError):
            self.run_pull()
        (path / "lock").unlink()
        self.root.chmod(0o777)
        try:
            with self.assertRaises(pull.SafeError):
                self.run_pull()
        finally:
            self.root.chmod(0o700)
        self.assertEqual(self.transport.gets, [])

    def test_state_corruption_context_change_and_hardlinks_fail_closed(self):
        self.run_pull()
        path = self.config["state_dir"] / "state.json"
        good = path.read_bytes()
        for content in (b"null", b'{"schema_version":1}', good.replace(b'"site_id":7', b'"site_id":8')):
            path.write_bytes(content)
            with self.assertRaises(pull.SafeError):
                self.run_pull()
        path.write_bytes(good)
        path.chmod(0o644)
        with self.assertRaises(pull.SafeError):
            self.run_pull()
        path.chmod(0o600)
        os.link(path, self.root / "linked")
        with self.assertRaises(pull.SafeError):
            self.run_pull()

    def test_version_reuse_with_changed_content_rejected(self):
        self.run_pull()
        self.transport.current = envelope(offset=20)
        with self.assertRaises(pull.SafeError):
            self.run_pull()
        self.assertEqual(self.dsm.calls.count("set"), 1)

    def test_unsafe_backup_symlink_prevents_set(self):
        self.config["state_dir"].mkdir(mode=0o700)
        (self.config["state_dir"] / "backups").symlink_to(self.root)
        with self.assertRaises(pull.SafeError):
            self.run_pull()
        self.assertNotIn("set", self.dsm.calls)

    def test_private_backup_retention_is_bounded(self):
        with patch("synology.dhcp_pull.BACKUP_LIMIT", 2):
            for number in range(4):
                self.transport.current = envelope(version=f"v{number}", offset=number * 10)
                self.assertEqual(self.run_pull(), 0)
        directory = self.config["state_dir"] / "backups"
        backups = sorted(directory.iterdir())
        self.assertEqual(len(backups), 2)
        self.assertEqual(
            json.loads((backups[-1] / "reservations.json").read_text()),
            envelope(version="v2", offset=20)["payload"],
        )

    def test_unknown_backup_files_stop_writes_without_deleting_them(self):
        self.run_pull()
        directory = self.config["state_dir"] / "backups"
        unexpected = directory / "operator-note"
        unexpected.write_text("keep")
        self.transport.current = envelope(version="v2", offset=20)
        count = self.dsm.calls.count("set")
        with self.assertRaises(pull.SafeError) as error:
            self.run_pull()
        self.assertEqual(error.exception.code, "unsafe_backup")
        self.assertEqual(self.dsm.calls.count("set"), count)
        self.assertEqual(unexpected.read_text(), "keep")

    def test_retention_preserves_current_backup_after_clock_rollback(self):
        with pull.Store(self.config) as store:
            for _ in range(2):
                store.backup(self.dsm.response(self.dsm.live), self.dsm.live)
            directory = self.config["state_dir"] / "backups"
            for index, backup in enumerate(sorted(directory.iterdir())):
                backup.rename(directory / f"dsm-eth0-29990101T00000000000{index}Z-abcdefgh")
            with patch("synology.dhcp_pull.BACKUP_LIMIT", 2):
                store.backup(self.dsm.response(self.dsm.live), self.dsm.live)
        self.assertEqual(len(list(directory.iterdir())), 2)
        self.assertEqual(sum(not child.name.startswith("dsm-eth0-2999") for child in directory.iterdir()), 1)


class SchemaConfigTests(SimpleTestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix=".dhcp-tests-", dir=Path.cwd())
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.path = self.root / "pull.ini"
        self.text = (
            "[dhcp_pull]\nbase_url = https://example.invalid/prefix\nsite_id = 7\n"
            "ifname = eth0\nsubnet = 192.168.1.0/24\ntoken = test-only-not-a-credential\n"
            f"state_dir = {self.root / 'state'}\ntimeout = 3\n"
        )
        self.write()
        self.config = pull.load_config(self.path)

    def write(self, text=None):
        self.path.write_text(self.text if text is None else text)
        self.path.chmod(0o600)

    def test_config_rejects_insecure_url_credentials_paths_and_unknown_options(self):
        for old, new in (
            ("https://", "http://"), ("example.invalid", "user:pass@example.invalid"),
            ("/prefix", "/prefix?token=secret"), ("/prefix", "/prefix#fragment"),
            ("site_id = 7", "site_id = 0"), ("site_id = 7", "site_id = 07"),
            ("ifname = eth0", "ifname = ../eth0"), ("192.168.1.0/24", "192.168.1.1/24"),
            ("192.168.1.0/24", "192.168.0.0/16"), ("timeout = 3", "timeout = 0"),
            ("test-only-not-a-credential", "CHANGE_ME_BEFORE_USE"),
            (str(self.root / "state"), "relative/state"),
        ):
            self.write(self.text.replace(old, new))
            with self.subTest(new=new), self.assertRaises(pull.SafeError):
                pull.load_config(self.path)
        self.write(self.text + "insecure = true\n")
        with self.assertRaises(pull.SafeError):
            pull.load_config(self.path)

    def test_private_config_regular_file_ownership_mode_and_size(self):
        self.path.chmod(0o644)
        with self.assertRaises(pull.SafeError):
            pull.load_config(self.path)
        self.path.chmod(0o400)
        self.assertEqual(pull.load_config(self.path)["site_id"], 7)
        self.path.chmod(0o600)
        original = self.path.read_bytes()
        self.path.unlink()
        target = self.root / "target"
        target.write_bytes(original)
        target.chmod(0o600)
        self.path.symlink_to(target)
        with self.assertRaises(OSError):
            pull.load_config(self.path)
        self.path.unlink()
        self.write("x" * (pull.MAX_CONFIG + 1))
        with self.assertRaises(pull.SafeError):
            pull.load_config(self.path)
        self.write()
        with patch("synology.dhcp_pull.os.geteuid", return_value=os.geteuid() + 1):
            with self.assertRaises(pull.SafeError):
                pull.load_config(self.path)

    def test_strict_envelope_schema_metadata_subnet_checksum(self):
        good = envelope()
        self.assertEqual(pull.validate_envelope(good, self.config), good)
        for key, value in (
            ("schema_version", True), ("schema_version", 2), ("site_id", True),
            ("site_id", 8), ("subnet", "192.168.2.0/24"), ("version", 'x"\r\n'),
            ("version", ""), ("sha256", "0" * 64), ("destructive_authorized", 1),
            ("published_at", "2026-99-14T00:00:00Z"), ("published_at", "2026-10-14"),
            ("published_at", "2026-10-14T00:00:00"),
        ):
            bad = copy.deepcopy(good)
            bad[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(pull.SafeError):
                pull.validate_envelope(bad, self.config)
        for bad in ({**good, "extra": True}, {key: value for key, value in good.items() if key != "payload"}):
            with self.assertRaises(pull.SafeError):
                pull.validate_envelope(bad, self.config)

    def test_invalid_payload_interface_ip_network_endpoints_mac_and_duplicates(self):
        for field, value in (
            ("ip", "192.168.2.1"), ("ip", "192.168.1.0"), ("ip", "192.168.1.255"),
            ("ip", "2001:db8::1"), ("mac", "01:00:00:00:00:01"),
            ("hostname", "bad\nname"), ("hostname", "a" * 254),
        ):
            bad = envelope()
            bad["payload"]["reservationData"][0][field] = value
            bad["sha256"] = pull.digest(bad["payload"])
            with self.subTest(field=field, value=value), self.assertRaises(pull.SafeError):
                pull.validate_envelope(bad, self.config)
        bad = envelope()
        bad["payload"]["ifname"] = "bond0"
        bad["sha256"] = pull.digest(bad["payload"])
        with self.assertRaises(pull.SafeError):
            pull.validate_envelope(bad, self.config)
        bad = envelope()
        bad["payload"]["reservationData"].append(bad["payload"]["reservationData"][0])
        bad["sha256"] = pull.digest(bad["payload"])
        with self.assertRaises(pull.SafeError):
            pull.validate_envelope(bad, self.config)

    def test_checksum_is_ascii_canonical_with_unicode(self):
        value = envelope()
        value["payload"]["reservationData"][0]["hostname"] = "höst"
        value["sha256"] = pull.digest(value["payload"])
        self.assertEqual(pull.validate_envelope(value, self.config), value)
        self.assertIn(b"\\u00f6", json.dumps(value["payload"], sort_keys=True, separators=(",", ":"),
                                         ensure_ascii=True).encode("ascii"))

    def test_copied_scripts_standalone_without_repository_or_packages(self):
        for module in (pull, dsm_apply):
            (self.root / Path(module.__file__).name).write_bytes(Path(module.__file__).read_bytes())
        result = subprocess.run(
            [sys.executable, "-S", str(self.root / "dhcp_pull.py"), "--help"],
            cwd=self.root, capture_output=True, text=True, timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("--reconcile", result.stdout)

    def test_main_fixed_redacted_errors_and_exit_codes(self):
        for exception, expected in (
            (pull.SafeError("already_running"), 3),
            (pull.SafeError("invalid_response"), 1), (OSError("secret-token"), 1),
            (subprocess.TimeoutExpired("secret-token", 120), 1),
        ):
            output = io.StringIO()
            with patch("synology.dhcp_pull.run", side_effect=exception), patch("sys.stderr", output):
                self.assertEqual(pull.main(["--config", str(self.path)]), expected)
            self.assertNotIn("secret-token", output.getvalue())
            self.assertIn("DHCP pull stopped:", output.getvalue())


class FakeResponse(io.BytesIO):
    def __init__(self, body=b"{}", code=200, headers=None):
        super().__init__(body)
        self.code = code
        self.headers = headers or {}


class TransportTests(SimpleTestCase):
    def setUp(self):
        self.config = {
            "base_url": "https://example.invalid/prefix", "site_id": 7,
            "token": "test-only-not-a-credential", "timeout": 3,
        }

    def test_tls_verified_no_redirects_proxies_and_auth_header_only(self):
        with patch("synology.dhcp_pull.urllib.request.build_opener") as build:
            transport = pull.Transport(self.config)
        handlers = build.call_args.args
        self.assertEqual(handlers[0].proxies, {})
        self.assertEqual(handlers[1]._context.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(handlers[1]._context.check_hostname)
        self.assertIsInstance(handlers[2], pull.NoRedirect)
        self.assertIsNone(handlers[2].redirect_request(None, None, 302, "", {}, "http://attacker.invalid"))
        transport.opener.open.return_value = FakeResponse()
        transport.request("GET", "latest", conditional='"v1"')
        request = transport.opener.open.call_args.args[0]
        self.assertEqual(request.full_url, "https://example.invalid/prefix/api/dhcp/sites/7/latest/")
        self.assertEqual(request.get_header("Authorization"), "Bearer " + self.config["token"])
        self.assertEqual(request.get_header("If-none-match"), '"v1"')
        self.assertNotIn(self.config["token"], request.full_url)
        self.assertEqual(transport.opener.open.call_args.kwargs["timeout"], 3)

    def test_optional_ca_and_exact_ack_json(self):
        with patch("synology.dhcp_pull.ssl.create_default_context") as context, \
                patch("synology.dhcp_pull.urllib.request.build_opener") as build, \
                patch("synology.dhcp_pull.read_private", return_value=b"private-pem-data") as read:
            transport = pull.Transport({**self.config, "ca_file": "/private/ca.pem"})
        read.assert_called_once_with("/private/ca.pem", pull.MAX_BODY)
        context.assert_called_once_with(cadata="private-pem-data")
        build.return_value.open.return_value = FakeResponse(b"", 204)
        ack = pull.acknowledgement(envelope(), "rejected", "dsm_drift")
        self.assertEqual(transport.request("POST", "results", ack)[0], 204)
        request = transport.opener.open.call_args.args[0]
        self.assertEqual(json.loads(request.data), ack)
        self.assertEqual(set(ack), {"schema_version", "version", "sha256", "status", "diagnostic", "report_id"})
        self.assertEqual(request.get_header("Content-type"), "application/json")

    def test_unsafe_ca_fails_before_ssl_or_request(self):
        with patch("synology.dhcp_pull.read_private", side_effect=pull.SafeError("unsafe_file")), \
                patch("synology.dhcp_pull.ssl.create_default_context") as context, \
                patch("synology.dhcp_pull.urllib.request.build_opener") as build:
            with self.assertRaises(pull.SafeError):
                pull.Transport({**self.config, "ca_file": "/private/ca.pem"})
        context.assert_not_called()
        build.assert_not_called()

    def test_http_redirect_auth_server_errors_and_network_fail_closed(self):
        with patch("synology.dhcp_pull.urllib.request.build_opener") as build:
            transport = pull.Transport(self.config)
        for code in (301, 302, 307, 308, 401, 403, 404, 500):
            build.return_value.open.side_effect = urllib.error.HTTPError(
                "https://example.invalid", code, "private-server-message", {}, io.BytesIO(b"private-body"),
            )
            with self.subTest(code=code), self.assertRaises(pull.SafeError) as error:
                transport.request("GET", "latest")
            self.assertEqual(error.exception.code, "http_failed")
        for error in (urllib.error.URLError("private-message"), TimeoutError("private-message"),
                      http.client.BadStatusLine("private-message")):
            build.return_value.open.side_effect = error
            with self.assertRaises(pull.SafeError) as caught:
                transport.request("GET", "latest")
            self.assertEqual(caught.exception.code, "network_failed")

    def test_bounded_http_body_with_and_without_content_length(self):
        with patch("synology.dhcp_pull.urllib.request.build_opener") as build:
            transport = pull.Transport(self.config)
        for response in (
            FakeResponse(headers={"Content-Length": str(pull.MAX_BODY + 1)}),
            FakeResponse(headers={"Content-Length": "-1"}),
            FakeResponse(b"x" * (pull.MAX_BODY + 1)),
        ):
            build.return_value.open.return_value = response
            with self.assertRaises(pull.SafeError) as error:
                transport.request("GET", "latest")
            self.assertEqual(error.exception.code, "size_limit")

    def test_deadline_and_304_http_error_response(self):
        with patch("synology.dhcp_pull.urllib.request.build_opener") as build:
            transport = pull.Transport(self.config)
        build.return_value.open.return_value = FakeResponse()
        with patch("synology.dhcp_pull.time.monotonic", side_effect=[0, 4]):
            with self.assertRaises(pull.SafeError) as error:
                transport.request("GET", "latest")
        self.assertEqual(error.exception.code, "network_timeout")
        build.return_value.open.side_effect = urllib.error.HTTPError(
            "https://example.invalid", 304, "not modified", {"ETag": '"v1"'}, io.BytesIO(b""),
        )
        self.assertEqual(transport.request("GET", "latest", conditional='"v1"'), (304, '"v1"', b""))

    def test_bounded_dsm_stdout_stderr_timeout_and_manual_api_unchanged(self):
        self.assertEqual(dsm_apply.bounded_output(
            [sys.executable, "-c", 'print(\'{"success":true}\')'], 1024,
        ).strip(), '{"success":true}')
        for stream in ("stdout", "stderr"):
            with self.subTest(stream=stream), self.assertRaises(ValueError):
                dsm_apply.bounded_output(
                    [sys.executable, "-c", f"import sys;sys.{stream}.write('x'*2048)"], 1024,
                )
        with patch("synology.dsm_apply.time.monotonic", side_effect=[0, 121]):
            with self.assertRaises(subprocess.TimeoutExpired):
                dsm_apply.bounded_output([sys.executable, "-c", "import time;time.sleep(2)"], 1024)

    def test_optional_bound_reuses_shared_fixed_api_command_and_parser(self):
        with patch("synology.dsm_apply.bounded_output", return_value='{"success":true}') as bounded, \
                patch("synology.dsm_apply.subprocess.run") as run:
            self.assertEqual(dsm_apply.call_api("get", "eth0", max_output=1024), {"success": True})
            run.assert_not_called()
            arguments, maximum = bounded.call_args.args
            self.assertEqual(maximum, 1024)
            self.assertEqual(arguments, [
                "/usr/syno/bin/synowebapi", "--exec",
                "api=SYNO.Network.DHCPServer.Reservation", "method=get", "version=3",
                'ifname="eth0"',
            ])
            dsm_apply.call_api("set", "eth0", [], max_output=1024)
            self.assertIn("version=2", bounded.call_args.args[0])
            self.assertIn("reservationData=[]", bounded.call_args.args[0])
