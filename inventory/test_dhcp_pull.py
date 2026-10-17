import copy
import errno
import http.client
import io
import json
import os
from pathlib import Path
import ssl
import stat
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
        # Execution identity is tested separately; keep real filesystem ownership checks.
        patch("synology.dhcp_pull.require_root").start()
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

    def main_output(self, expected_exit, reconcile=False):
        stdout, stderr = io.StringIO(), io.StringIO()
        argv = ["--config", "/private/pull.ini"] + (["--reconcile"] if reconcile else [])
        with patch.object(pull, "load_config", return_value=self.config), \
                patch("sys.stdout", stdout), patch("sys.stderr", stderr):
            self.assertEqual(pull.main(argv), expected_exit)
        self.assertEqual(stderr.getvalue(), "")
        return stdout.getvalue()

    def test_failed_run_surfaces_recorded_diagnostic_in_summary_and_last_report(self):
        for attribute, diagnostic in (("fail_read", "dsm_failed"), ("fail_set", "dsm_failed"),
                                      ("wrong_verification", "verification_failed")):
            with self.subTest(diagnostic=diagnostic, attribute=attribute):
                self.install_state()
                self.dsm = FakeDSM(payload(2, 10))
                setattr(self.dsm, attribute, True)
                patch("synology.dsm_apply.call_api", side_effect=self.dsm).start()
                text = self.main_output(1)
                self.assertEqual(text, f"DHCP pull failed; retry required. Diagnostic: {diagnostic}.\n")
                self.assertNotIn("private-output", text)
                self.assertNotIn(self.config["token"], text)
                self.assertNotIn("example.invalid", text)
                self.assertEqual(self.state()["last_report"], {
                    "version": "v1", "sha256": self.transport.current["sha256"],
                    "status": "failed", "diagnostic": diagnostic,
                })
                self.assertEqual(set(self.transport.posts[-1]),
                                 {"schema_version", "version", "sha256", "status", "diagnostic", "report_id"})

    def test_rejected_run_surfaces_recorded_diagnostic(self):
        self.assertEqual(self.main_output(0), "DHCP pull completed.\n")
        self.assertNotIn("diagnostic", self.state()["last_report"])
        self.transport.not_modified = True
        self.dsm.live = payload(2, 30)
        self.assertEqual(self.main_output(2),
                         "DHCP pull rejected; operator review required. Diagnostic: dsm_drift.\n")
        self.assertEqual(self.state()["last_report"]["diagnostic"], "dsm_drift")
        self.dsm.live = self.transport.current["payload"]
        self.assertEqual(self.main_output(0, reconcile=True), "DHCP pull completed.\n")
        self.assertNotIn("diagnostic", self.state()["last_report"])

    def test_undelivered_failure_surfaces_pending_diagnostic(self):
        self.dsm.fail_read = True
        self.transport.fail_post = True
        self.assertEqual(self.main_output(1), "DHCP pull failed; retry required. Diagnostic: dsm_failed.\n")
        self.assertIsNone(self.state()["last_report"])
        self.assertEqual(self.state()["pending"]["diagnostic"], "dsm_failed")

    def test_undelivered_success_has_no_diagnostic(self):
        self.transport.fail_post = True
        self.assertEqual(self.main_output(1), "DHCP pull failed; retry required.\n")

    def test_last_report_diagnostic_state_validation(self):
        published = envelope()
        base = {"version": published["version"], "sha256": published["sha256"]}
        for last, valid in (
            (dict(base, status="failed"), True),
            (dict(base, status="failed", diagnostic="dsm_failed"), True),
            (dict(base, status="rejected", diagnostic="dsm_drift"), True),
            (dict(base, status="failed", diagnostic="secret-token"), False),
            (dict(base, status="failed", diagnostic=None), False),
            (dict(base, status="applied", diagnostic="dsm_failed"), False),
            (dict(base, status="failed", extra="x"), False),
        ):
            with self.subTest(last=last):
                state = pull.empty_state(self.config)
                state.update(fetched=published, last_report=last)
                if valid:
                    self.assertEqual(pull.validate_state(state, self.config)["last_report"], last)
                else:
                    with self.assertRaises(pull.SafeError) as raised:
                        pull.validate_state(state, self.config)
                    self.assertEqual(raised.exception.code, "invalid_state")

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

    def test_state_lock_and_backup_file_diagnostics_identify_exact_leaf(self):
        self.run_pull()
        directory = self.config["state_dir"]
        backup, = (directory / "backups").iterdir()
        for path, context in (
            (directory / "lock", "state lock"), (directory / "state.json", "state"),
            (backup / "response.json", "backups"), (backup / "reservations.json", "backups"),
        ):
            path.chmod(0o644)
            try:
                with self.subTest(path=path), self.assertRaises(pull.SafeError) as raised:
                    if context == "backups":
                        with pull.Store(self.config) as store:
                            store.prune_backups(directory / "backups", backup)
                    else:
                        self.run_pull()
                self.assertEqual(raised.exception.code, "unsafe_file")
                self.assertEqual(raised.exception.diagnostic.path, path)
                self.assertEqual(raised.exception.diagnostic.context, context)
                self.assertIn("mode=0o0644", raised.exception.diagnostic.render())
                self.assertIn("mode=0o0600 nlink=1", raised.exception.diagnostic.render())
            finally:
                path.chmod(0o600)
        with pull.Store(self.config) as store:
            path = directory / "state.json"
            path.chmod(0o400)
            try:
                with self.assertRaises(pull.SafeError) as raised:
                    store.save(self.state())
                self.assertEqual(raised.exception.diagnostic.path, path)
                self.assertEqual(raised.exception.code, "unsafe_file")
            finally:
                path.chmod(0o600)
        backup.chmod(0o750)
        try:
            with pull.Store(self.config) as store, self.assertRaises(pull.SafeError) as raised:
                store.prune_backups(directory / "backups", backup)
            self.assertEqual(raised.exception.code, "unsafe_backup")
            self.assertEqual(raised.exception.diagnostic.path, backup)
        finally:
            backup.chmod(0o700)

    def test_backup_oserror_keeps_persistence_code_context_and_no_remote_details(self):
        original = Path.lstat
        directory = self.config["state_dir"] / "backups"

        def lstat(path):
            if path == directory:
                raise PermissionError(errno.EACCES, "private-token-and-body")
            return original(path)

        output = io.StringIO()
        with patch.object(Path, "lstat", autospec=True, side_effect=lstat), \
                patch.object(pull, "load_config", return_value=self.config), patch("sys.stderr", output):
            self.assertEqual(pull.main(["--config", "/private/pull.ini"]), 1)
        text = output.getvalue()
        self.assertIn("DHCP pull stopped: persistence_failed.", text)
        self.assertIn(f'backups: lstat directory path="{directory}"', text)
        self.assertIn("permission_denied", text)
        self.assertNotIn("private-token-and-body", text)
        self.assertNotIn("set", self.dsm.calls)
        self.assertEqual(self.transport.posts, [])

    def test_state_replace_and_sync_failures_keep_local_context(self):
        with pull.Store(self.config) as store:
            for function, operation, expected_path in (
                ("replace", "replace file", store.path / "state.json"),
                ("fsync", "sync temporary file", None),
            ):
                with self.subTest(function=function), \
                        patch.object(pull.os, function, side_effect=OSError(errno.ENOSPC, "private-body")):
                    with self.assertRaises(OSError) as raised:
                        store.save(pull.empty_state(self.config))
                diagnostic = raised.exception.diagnostic
                self.assertEqual(diagnostic.operation, operation)
                if expected_path is not None:
                    self.assertEqual(diagnostic.path, expected_path)
                else:
                    self.assertEqual(diagnostic.path.parent, store.path)
                    self.assertTrue(diagnostic.path.name.startswith(".state-"))
                self.assertEqual(diagnostic.failed, ("no_space",))
                self.assertNotIn("private-body", diagnostic.render())
                self.assertEqual(list(store.path.glob(".state-*")), [])

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


class FilesystemDiagnosticTests(SimpleTestCase):
    def setUp(self):
        effective_uid = patch("synology.dhcp_pull.os.geteuid", return_value=1234)
        effective_uid.start()
        self.addCleanup(effective_uid.stop)

    @staticmethod
    def metadata(mode=stat.S_IFDIR | 0o755, uid=0, nlink=1):
        return os.stat_result((mode, 0, 0, nlink, uid, 0, 0, 0, 0, 0))

    def cli_error(self, error, code, expected_exit=1):
        output = io.StringIO()
        with patch.object(pull, "require_root"), \
                patch.object(pull, "load_config", return_value={}), \
                patch.object(pull, "run", side_effect=error), patch("sys.stderr", output):
            self.assertEqual(pull.main(["--config", "/private/pull.ini"]), expected_exit)
        text = output.getvalue()
        self.assertTrue(text.startswith("DHCP pull stopped: " + code + "."))
        self.assertEqual(len(text.splitlines()), 1)
        return text

    def test_exact_first_failing_ancestor_including_root(self):
        path = Path("/private/nested/pull.ini")
        parents = [Path("/"), Path("/private"), Path("/private/nested")]
        for index, bad in enumerate(parents):
            checked = []

            def lstat(parent):
                checked.append(parent)
                return self.metadata(mode=stat.S_IFDIR | (0o777 if parent == bad else 0o755))

            with self.subTest(parent=bad), patch.object(Path, "lstat", autospec=True, side_effect=lstat):
                with self.assertRaises(pull.SafeError) as raised:
                    pull.secure_parents(path, "config")
                error = raised.exception
                self.assertEqual(error.code, "unsafe_path")
                self.assertEqual(error.diagnostic.path, bad)
                self.assertEqual(checked, parents[:index + 1])
                text = self.cli_error(error, "unsafe_path")
                self.assertIn(f'path="{bad}"', text)
                self.assertIn("config: validate ancestor", text)
                self.assertIn("mode=0o0777", text)
                self.assertIn("mode&0o0022=0", text)

    def test_parent_reasons_and_all_observed_metadata(self):
        for mode, uid, failed in (
            (stat.S_IFLNK | 0o755, 0, ("symlink",)),
            (stat.S_IFREG | 0o755, 0, ("nondirectory",)),
            (stat.S_IFIFO | 0o700, 0, ("nondirectory",)),
            (stat.S_IFDIR | 0o755, 42, ("untrusted_owner",)),
            (stat.S_IFDIR | 0o775, 0, ("group_or_other_writable",)),
            (stat.S_IFDIR | 0o757, 0, ("group_or_other_writable",)),
            (stat.S_IFLNK | 0o777, 42,
             ("symlink", "untrusted_owner", "group_or_other_writable")),
        ):
            def lstat(parent):
                return self.metadata(mode, uid) if parent == Path("/bad") else self.metadata()

            with self.subTest(mode=mode, uid=uid), \
                    patch.object(Path, "lstat", autospec=True, side_effect=lstat):
                with self.assertRaises(pull.SafeError) as raised:
                    pull.secure_parents(Path("/bad/child/leaf"), "CA")
                diagnostic = raised.exception.diagnostic
                self.assertEqual(diagnostic.path, Path("/bad"))
                self.assertEqual(diagnostic.failed, failed)
                text = self.cli_error(raised.exception, "unsafe_path")
                self.assertIn(f"uid={uid}", text)
                self.assertIn(f"mode=0o{stat.S_IMODE(mode):04o}", text)
                self.assertIn("euid=1234", text)
                self.assertIn("uid=0 or 1234", text)
                self.assertIn("type=", text)

    def test_nonabsolute_path_is_not_inspected(self):
        with patch.object(Path, "lstat") as lstat:
            with self.assertRaises(pull.SafeError) as raised:
                pull.secure_parents(Path("relative/leaf"), "state")
        lstat.assert_not_called()
        self.assertEqual(raised.exception.code, "unsafe_path")
        self.assertIn("nonabsolute_path", raised.exception.diagnostic.render())
        self.assertIn("expected absolute path", raised.exception.diagnostic.render())

    def test_allowed_parent_metadata_is_unchanged(self):
        for uid in (0, 1234):
            for mode in (0o700, 0o755, 0o555, 0o2755):
                with self.subTest(uid=uid, mode=mode), \
                        patch.object(Path, "lstat", return_value=self.metadata(stat.S_IFDIR | mode, uid)):
                    pull.secure_parents(Path("/private/leaf"))

    def test_file_rejections_and_allowed_modes_are_unchanged(self):
        for mode, uid, nlink, failed in (
            (stat.S_IFREG | 0o644, 1234, 1, "mode_not_private"),
            (stat.S_IFREG | 0o600, 0, 1, "untrusted_owner"),
            (stat.S_IFREG | 0o600, 1234, 2, "link_count_not_one"),
            (stat.S_IFDIR | 0o600, 1234, 1, "not_regular_file"),
            (stat.S_IFIFO | 0o600, 1234, 1, "not_regular_file"),
            (stat.S_IFLNK | 0o600, 1234, 1, "symlink"),
        ):
            with self.subTest(mode=mode, uid=uid, nlink=nlink), \
                    patch.object(pull.os, "fstat", return_value=self.metadata(mode, uid, nlink)):
                with self.assertRaises(pull.SafeError) as raised:
                    pull.secure_file(10, path=Path("/private/pull.ini"), context="config")
                text = self.cli_error(raised.exception, "unsafe_file")
                self.assertIn(failed, text)
                self.assertIn("config: validate file", text)
                self.assertIn("uid=1234 (euid) mode=0o0400 or 0o0600 nlink=1", text)
        for writable, mode, allowed in (
            (False, 0o400, True), (False, 0o600, True), (True, 0o600, True),
            (True, 0o400, False), (False, 0o660, False), (True, 0o1600, False),
        ):
            with self.subTest(writable=writable, mode=mode), \
                    patch.object(pull.os, "fstat", return_value=self.metadata(stat.S_IFREG | mode, 1234)):
                if allowed:
                    pull.secure_file(10, writable)
                else:
                    with self.assertRaises(pull.SafeError):
                        pull.secure_file(10, writable)

    def test_state_directory_reports_checked_metadata_and_closes_fd(self):
        for mode, uid, failed in (
            (0o755, 1234, "mode_not_private"), (0o700, 0, "untrusted_owner"),
        ):
            with self.subTest(mode=mode, uid=uid), patch.object(pull, "secure_parents"), \
                    patch.object(Path, "mkdir", side_effect=FileExistsError), \
                    patch.object(pull.os, "open", return_value=10), \
                    patch.object(pull.os, "fstat", return_value=self.metadata(stat.S_IFDIR | mode, uid)), \
                    patch.object(pull.os, "close") as close:
                with self.assertRaises(pull.SafeError) as raised:
                    with pull.Store({"state_dir": Path("/private/state")}):
                        self.fail("Unsafe directory was accepted")
                text = self.cli_error(raised.exception, "unsafe_directory")
                self.assertIn('state: validate directory path="/private/state"', text)
                self.assertIn(failed, text)
                self.assertIn("expected type=directory uid=1234 (euid) mode=0o0700", text)
                close.assert_called_once_with(10)

    def test_backup_directory_type_owner_and_mode(self):
        for mode, uid, failed in (
            (stat.S_IFLNK | 0o777, 1234, "symlink"),
            (stat.S_IFREG | 0o700, 1234, "nondirectory"),
            (stat.S_IFDIR | 0o700, 42, "untrusted_owner"),
            (stat.S_IFDIR | 0o750, 1234, "mode_not_private"),
        ):
            with self.subTest(mode=mode, uid=uid), patch.object(Path, "mkdir"), \
                    patch.object(Path, "lstat", return_value=self.metadata(mode, uid)):
                with self.assertRaises(pull.SafeError) as raised:
                    pull.Store({"state_dir": Path("/private/state")}).backup({}, {})
                text = self.cli_error(raised.exception, "unsafe_directory")
                self.assertIn('path="/private/state/backups"', text)
                self.assertIn(failed, text)

    def test_local_oserror_context_uses_allowlisted_reasons_not_exception_text(self):
        for number, reason in (
            (errno.ENOENT, "missing"), (errno.EACCES, "permission_denied"),
            (errno.EPERM, "permission_denied"), (errno.ELOOP, "symlink_rejected"),
            (errno.ENOTDIR, "not_directory_or_symlink_rejected"), (errno.EIO, "io_error"),
            (errno.ENOSPC, "no_space"), (errno.EROFS, "read_only_filesystem"),
            (errno.EBADF, "filesystem_error"),
        ):
            original = OSError(number, "secret-token\nAuthorization: private-server-body")
            with self.subTest(errno=number), patch.object(Path, "lstat", side_effect=original):
                with self.assertRaises(OSError) as raised:
                    pull.secure_parents(Path("/private/leaf"), "config")
                self.assertIs(raised.exception, original)
                self.assertEqual(raised.exception.diagnostic.path, Path("/"))
                text = self.cli_error(raised.exception, "local_or_transport_failure")
                self.assertIn(reason, text)
                self.assertIn(f"errno={number}", text)
                self.assertIn("lstat ancestor", text)
                self.assertNotIn("secret-token", text)
                self.assertNotIn("Authorization", text)
                self.assertNotIn("private-server-body", text)
        with patch.object(pull, "secure_parents"), \
                patch.object(pull.os, "open", side_effect=OSError(errno.ELOOP, "private-data")):
            with self.assertRaises(OSError) as raised:
                pull.read_private("/private/ca.pem", 100, "CA")
            text = self.cli_error(raised.exception, "local_or_transport_failure")
            self.assertIn('CA: open file (no symlinks) path="/private/ca.pem"', text)
            self.assertIn("symlink_rejected", text)
            self.assertNotIn("private-data", text)

    def test_unusual_paths_are_escaped_bounded_and_single_line(self):
        for path in ("/private/line\nbreak\r\t\x1b\x00\u2028\u202e.pem", "/private/" + "\n" * 10000):
            error = pull.SafeError("unsafe_path", pull.FilesystemDiagnostic(
                Path(path), "config", "validate ancestor", ("group_or_other_writable",),
            ))
            text = self.cli_error(error, "unsafe_path")
            self.assertLess(len(text), 500)
            self.assertTrue(text[:-1].isascii())
            self.assertNotIn("\x1b", text)
            self.assertIn("\\n", text)
        self.assertIn("[truncated]", text)

    def test_code_only_and_unknown_exceptions_keep_exact_redacted_output(self):
        for error, code, exit_code in (
            (pull.SafeError("already_running"), "already_running", 3),
            (pull.SafeError("unsafe_path"), "unsafe_path", 1),
            (pull.SafeError("unsafe_file"), "unsafe_file", 1),
            (OSError("private-data"), "local_or_transport_failure", 1),
            (ValueError("private-data"), "local_or_transport_failure", 1),
            (subprocess.TimeoutExpired("private-data", 1), "local_or_transport_failure", 1),
        ):
            self.assertEqual(self.cli_error(error, code, exit_code), f"DHCP pull stopped: {code}.\n")

    def test_local_diagnostic_cannot_be_sent_as_remote_ack(self):
        diagnostic = pull.FilesystemDiagnostic(
            Path("/private/state"), "state", "validate directory", ("mode_not_private",),
        )
        with self.assertRaises(pull.SafeError) as raised:
            pull.acknowledgement(envelope(), "failed", diagnostic)
        self.assertEqual(raised.exception.code, "invalid_state")


class RootPreflightTests(SimpleTestCase):
    def setUp(self):
        self.identity = patch.object(pull.os, "geteuid", return_value=1001).start()
        self.store = patch.object(pull, "Store").start()
        self.transport = patch.object(pull, "Transport").start()
        self.dsm = patch.object(dsm_apply, "call_api").start()
        self.load_config = patch.object(pull, "load_config").start()
        self.addCleanup(patch.stopall)

    def assert_no_operations(self):
        self.store.assert_not_called()
        self.transport.assert_not_called()
        self.dsm.assert_not_called()
        self.load_config.assert_not_called()

    def test_non_root_run_fails_before_state_transport_or_dsm(self):
        for reconcile in (False, True):
            outcome = {}
            config = {"token": "test-only-not-a-credential"}
            with self.subTest(reconcile=reconcile), self.assertRaises(pull.SafeError) as raised:
                pull.run(config, reconcile, outcome)
            self.assertEqual(raised.exception.code, "requires_root")
            self.assertIsNone(raised.exception.diagnostic)
            self.assertEqual(config, {"token": "test-only-not-a-credential"})
            self.assertEqual(outcome, {})
            self.assert_no_operations()

    def test_non_root_cli_fails_before_config_read_with_fixed_instruction(self):
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch("sys.stdout", stdout), patch("sys.stderr", stderr):
            self.assertEqual(pull.main(["--config", "/private/missing.ini", "--reconcile"]), 1)
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(stderr.getvalue(), (
            "DHCP pull stopped: requires_root. "
            "Run as root or configure a DSM user-defined scheduled task as root.\n"
        ))
        self.assert_no_operations()

    def test_help_without_root_does_not_run_preflight(self):
        stdout = io.StringIO()
        with patch("sys.stdout", stdout), self.assertRaises(SystemExit) as raised:
            pull.main(["--help"])
        self.assertEqual(raised.exception.code, 0)
        self.assertIn("--config", stdout.getvalue())
        self.identity.assert_not_called()
        self.assert_no_operations()

    def test_root_cli_and_run_retain_normal_execution_and_exit_codes(self):
        self.identity.return_value = 0
        config = self.load_config.return_value
        store = self.store.return_value.__enter__.return_value
        for result, summary in (
            (0, "DHCP pull completed."),
            (1, "DHCP pull failed; retry required. Diagnostic: dsm_failed."),
            (2, "DHCP pull rejected; operator review required. Diagnostic: dsm_drift."),
        ):
            diagnostic = "dsm_failed" if result == 1 else "dsm_drift"
            store.load.return_value = {
                "pending": None, "last_report": {"status": "failed", "diagnostic": diagnostic},
            }
            stdout, stderr = io.StringIO(), io.StringIO()
            with self.subTest(result=result), patch.object(pull, "execute", return_value=result) as execute, \
                    patch("sys.stdout", stdout), patch("sys.stderr", stderr):
                self.assertEqual(pull.main(["--config", "/private/pull.ini"]), result)
            execute.assert_called_once_with(config, False, store, store.load.return_value)
            self.assertEqual(stdout.getvalue(), summary + "\n")
            self.assertEqual(stderr.getvalue(), "")
        self.assertEqual(self.identity.call_count, 6)

    def test_root_requirement_does_not_affect_pure_schema_helpers(self):
        value = envelope()
        self.assertEqual(pull.validate_envelope(value, {
            "site_id": 7, "ifname": "eth0", "subnet": "192.168.1.0/24",
        }), value)
        self.identity.assert_not_called()
        self.assert_no_operations()

    def test_requires_root_is_not_a_remote_diagnostic(self):
        self.assertNotIn("requires_root", pull.DIAGNOSTICS)
        with self.assertRaises(pull.SafeError) as raised:
            pull.acknowledgement(envelope(), "failed", "requires_root")
        self.assertEqual(raised.exception.code, "invalid_state")
        self.assert_no_operations()


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

    def test_http_requires_explicit_vpn_opt_in_and_https_remains_default(self):
        self.assertEqual(self.config["base_url"], "https://example.invalid/prefix")
        self.assertFalse(self.config["allow_http_over_vpn"])
        self.write(self.text.replace("https://", "http://"))
        with self.assertRaises(pull.SafeError):
            pull.load_config(self.path)
        self.write(self.text.replace("https://", "http://") + "allow_http_over_vpn = false\n")
        with self.assertRaises(pull.SafeError):
            pull.load_config(self.path)
        self.write(self.text.replace("https://", "http://") + "allow_http_over_vpn = true\n")
        config = pull.load_config(self.path)
        self.assertEqual(config["base_url"], "http://example.invalid/prefix")
        self.assertTrue(config["allow_http_over_vpn"])
        self.write(self.text + "allow_http_over_vpn = true\n")
        self.assertEqual(pull.load_config(self.path)["base_url"], "https://example.invalid/prefix")
        self.write(self.text + "allow_http_over_vpn = yes\n")
        with self.assertRaises(pull.SafeError):
            pull.load_config(self.path)

    def test_private_config_regular_file_ownership_mode_and_size(self):
        self.path.chmod(0o644)
        with self.assertRaises(pull.SafeError) as raised:
            pull.load_config(self.path)
        self.assertEqual(raised.exception.code, "unsafe_file")
        self.assertEqual(raised.exception.diagnostic.path, self.path)
        self.assertEqual(raised.exception.diagnostic.context, "config")
        self.assertIn("mode=0o0644", raised.exception.diagnostic.render())
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

    def test_config_ancestor_symlink_is_checked_lexically_not_resolved(self):
        link = self.root / "linked"
        link.symlink_to(self.root, target_is_directory=True)
        for path in (link / self.path.name, link / ".." / self.root.name / self.path.name):
            with self.subTest(path=path), self.assertRaises(pull.SafeError) as raised:
                pull.load_config(path)
            self.assertEqual(raised.exception.code, "unsafe_path")
            self.assertEqual(raised.exception.diagnostic.path, link)
            self.assertIn("symlink", raised.exception.diagnostic.failed)
            self.assertEqual(raised.exception.diagnostic.context, "config")

    def test_config_open_failure_and_nonabsolute_settings_have_safe_context(self):
        missing = self.root / "missing.ini"
        with self.assertRaises(OSError) as raised:
            pull.load_config(missing)
        self.assertEqual(raised.exception.diagnostic.path, missing)
        self.assertEqual(raised.exception.diagnostic.failed, ("missing",))
        for old, new, context in (
            (str(self.root / "state"), "relative/state", "state"),
            ("timeout = 3", "timeout = 3\nca_file = relative.pem", "CA"),
        ):
            self.write(self.text.replace(old, new))
            with self.assertRaises(pull.SafeError) as raised:
                pull.load_config(self.path)
            self.assertEqual(raised.exception.code, "invalid_config")
            self.assertEqual(raised.exception.diagnostic.context, context)
            self.assertEqual(raised.exception.diagnostic.failed, ("nonabsolute_path",))

    def test_relative_config_still_works_with_safe_ancestors(self):
        relative = self.path.relative_to(Path.cwd())
        self.assertEqual(pull.load_config(relative), self.config)

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
            with patch("synology.dhcp_pull.os.geteuid", return_value=0), \
                    patch("synology.dhcp_pull.load_config", return_value=self.config), \
                    patch("synology.dhcp_pull.run", side_effect=exception), patch("sys.stderr", output):
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

    def test_explicit_http_uses_same_authenticated_request_without_tls_downgrade(self):
        config = {**self.config, "base_url": "http://example.invalid/prefix",
                  "allow_http_over_vpn": True}
        with patch("synology.dhcp_pull.urllib.request.build_opener") as build:
            transport = pull.Transport(config)
        transport.opener.open.return_value = FakeResponse()
        transport.request("GET", "latest", conditional='"v1"')
        request = transport.opener.open.call_args.args[0]
        self.assertEqual(request.full_url, "http://example.invalid/prefix/api/dhcp/sites/7/latest/")
        self.assertEqual(request.get_header("Authorization"), "Bearer " + config["token"])
        self.assertEqual(request.get_header("If-none-match"), '"v1"')
        self.assertNotIn(config["token"], request.full_url)
        self.assertEqual(build.call_args.args[0].proxies, {})

    def test_optional_ca_and_exact_ack_json(self):
        with patch("synology.dhcp_pull.ssl.create_default_context") as context, \
                patch("synology.dhcp_pull.urllib.request.build_opener") as build, \
                patch("synology.dhcp_pull.read_private", return_value=b"private-pem-data") as read:
            transport = pull.Transport({**self.config, "ca_file": "/private/ca.pem"})
        read.assert_called_once_with("/private/ca.pem", pull.MAX_BODY, "CA")
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
