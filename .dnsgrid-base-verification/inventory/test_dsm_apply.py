import copy
from io import StringIO
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from unittest.mock import patch

from django.test import SimpleTestCase

from synology import dsm_apply


class DSMLocalApplyTests(SimpleTestCase):
    def test_copied_script_help_without_site_packages_or_repository(self):
        with tempfile.TemporaryDirectory() as directory:
            script = Path(directory) / "dsm_apply.py"
            script.write_bytes(Path(dsm_apply.__file__).read_bytes())
            result = subprocess.run(
                [sys.executable, "-I", "-S", str(script), "--help"],
                cwd=directory, capture_output=True, text=True, timeout=10,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("usage:", result.stdout)
        self.assertIn("--dry-run", result.stdout)

    def setUp(self):
        self.payload = {
            "ifname": "bond0",
            "reservationData": [
                {"mac": "02:aa:bb:cc:dd:ee", "ip": "10.24.17.50", "hostname": "alpha"},
            ],
        }
        self.response = self.response_for(self.payload)

    def response_for(self, payload):
        return {
            "success": True, "httpd_restart": False,
            "data": {"reservationList": {
                "ipv4": [
                    {"clid": item["mac"], "ip": item["ip"], "hostname": item["hostname"]}
                    for item in payload["reservationData"]
                ],
                "ipv6": [],
            }},
        }

    def test_read_conversion_preserves_mapping_and_empty_hostname(self):
        self.response["data"]["reservationList"]["ipv4"][0]["clid"] = "02:AA:BB:CC:DD:EE"
        self.assertEqual(dsm_apply.current_payload(self.response, "bond0"), self.payload)
        self.response["data"]["reservationList"]["ipv4"][0]["hostname"] = ""
        self.assertEqual(dsm_apply.current_payload(
            self.response, "bond0",
        )["reservationData"][0]["hostname"], "")
        del self.response["data"]["reservationList"]["ipv6"]
        self.assertEqual(len(dsm_apply.current_payload(self.response, "bond0")["reservationData"]), 1)

    def test_current_entries_fail_closed(self):
        for entry in (None, {}, {"clid": "invalid", "ip": "10.0.0.1", "hostname": "alpha"}):
            response = copy.deepcopy(self.response)
            response["data"]["reservationList"]["ipv4"] = [entry]
            with self.assertRaises(ValueError):
                dsm_apply.current_payload(response, "bond0")
        for response in ({}, {"success": False}, {"success": True}, {"success": True, "data": None}):
            with self.assertRaises(ValueError):
                dsm_apply.current_payload(response, "bond0")

    def test_payload_validation(self):
        self.assertEqual(dsm_apply.validate_payload({
            **self.payload, "ifname": "bond0.17",
        })["ifname"], "bond0.17")
        for field, value in (
            ("mac", None), ("mac", ""), ("mac", "00:00:00:00:00:00"),
            ("mac", "01:00:00:00:00:01"), ("ip", None), ("ip", "2001:db8::1"),
            ("ip", "invalid"), ("hostname", None), ("hostname", "bad\nname"),
        ):
            payload = copy.deepcopy(self.payload)
            payload["reservationData"][0][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                dsm_apply.validate_payload(payload)
        for field, value in (("ifname", "../etc"), ("ifname", "bond0\n"),
                             ("ifname", None), ("reservationData", {})):
            payload = {**self.payload, field: value}
            with self.assertRaises(ValueError):
                dsm_apply.validate_payload(payload)
        payload = copy.deepcopy(self.payload)
        payload["reservationData"] *= 2
        with self.assertRaises(ValueError):
            dsm_apply.validate_payload(payload)
        with self.assertRaises(ValueError):
            dsm_apply.validate_payload({**self.payload, "ipv6": []})

    def test_ipv6_fails_closed(self):
        for ipv6 in ([{"ip": "2001:db8::1"}], None, {}):
            self.response["data"]["reservationList"]["ipv6"] = ipv6
            with self.assertRaisesRegex(ValueError, "IPv6"):
                dsm_apply.current_payload(self.response, "bond0")

    @patch("synology.dsm_apply.subprocess.run")
    def test_api_versions_json_arguments_and_direct_array(self, run):
        run.return_value = subprocess.CompletedProcess([], 0, stdout='[Line 295] param={"ifname":"bond0"}\n{"success":true}')
        dsm_apply.call_api("get", "bond0")
        self.assertEqual(run.call_args.args[0], [
            "/usr/syno/bin/synowebapi", "--exec",
            "api=SYNO.Network.DHCPServer.Reservation", "method=get", "version=3",
            'ifname="bond0"',
        ])
        dsm_apply.call_api("set", "bond0", self.payload["reservationData"])
        args = run.call_args.args[0]
        self.assertIn("method=set", args)
        self.assertIn("version=2", args)
        self.assertEqual(json.loads(args[-1].split("=", 1)[1]), self.payload["reservationData"])
        self.assertTrue(run.call_args.kwargs["check"])
        self.assertNotIn("shell", run.call_args.kwargs)
        run.return_value.stdout = '{"success": false, "error":{"code":4300}}'
        with self.assertRaisesRegex(ValueError, "failed"):
            dsm_apply.call_api("get", "bond0")
        with self.assertRaises(ValueError):
            dsm_apply.parse_response("not JSON")

    def invoke(self, args=(), responses=None, answer="n", backup_failure=False):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            export = root / "export.json"
            export.write_text(json.dumps(self.payload))
            output, errors = StringIO(), StringIO()
            with (
                patch("synology.dsm_apply.call_api", side_effect=responses or [self.response]) as api,
                patch("builtins.input", return_value=answer) as prompt,
                patch("sys.stdout", output),
                patch("sys.stderr", errors),
            ):
                if backup_failure:
                    with patch("synology.dsm_apply.backup_reservations", side_effect=OSError("disk full")):
                        result = dsm_apply.main([str(export), "--backup-dir", str(root), *args])
                else:
                    result = dsm_apply.main([str(export), "--backup-dir", str(root), *args])
                backups = list(root.glob("dsm-bond0-*"))
                if backups:
                    backup = backups[0]
                    self.assertEqual(json.loads((backup / "response.json").read_text()), responses[0] if responses else self.response)
                    self.assertEqual(json.loads((backup / "reservations.json").read_text()),
                                     dsm_apply.current_payload(responses[0] if responses else self.response, "bond0"))
                    self.assertEqual(backup.stat().st_mode & 0o777, 0o700)
                    self.assertEqual((backup / "reservations.json").stat().st_mode & 0o777, 0o600)
                return result, api.call_args_list, prompt.call_count, output.getvalue(), errors.getvalue(), len(backups)

    def test_default_and_explicit_dry_run_back_up_without_writing_or_prompting(self):
        for args in ((), ("--dry-run",)):
            result, calls, prompts, output, errors, backups = self.invoke(args)
            self.assertEqual(result, 0, errors)
            self.assertEqual([call.args[0] for call in calls], ["get"])
            self.assertEqual(prompts, 0)
            self.assertEqual(backups, 1)
            self.assertIn("Dry run", output)

    def test_confirmation_declined(self):
        result, calls, prompts, output, errors, _ = self.invoke(("--apply",), answer="no")
        self.assertEqual(result, 0, errors)
        self.assertEqual(len(calls), 1)
        self.assertEqual(prompts, 1)
        self.assertIn("Aborted", output)

    def test_apply_and_yes_write_then_verify(self):
        original = self.response_for({**self.payload, "reservationData": []})
        for args in (("--apply",), ("--yes",)):
            result, calls, prompts, output, errors, backups = self.invoke(
                args, [original, original, {"success": True}, self.response], answer="y",
            )
            self.assertEqual(result, 0, errors)
            self.assertEqual([call.args[0] for call in calls], ["get", "get", "set", "get"])
            self.assertEqual(calls[2].args, ("set", "bond0", self.payload["reservationData"]))
            self.assertEqual(prompts, int(args == ("--apply",)))
            self.assertEqual(backups, 1)
            self.assertIn("+", output)
            self.assertIn("Applied and verified", output)

    def test_backup_failure_prevents_write(self):
        result, calls, _, _, errors, _ = self.invoke(("--yes",), backup_failure=True)
        self.assertEqual(result, 1)
        self.assertEqual(len(calls), 1)
        self.assertIn("disk full", errors)

    def test_changed_current_state_prevents_write(self):
        changed = self.response_for({**self.payload, "reservationData": []})
        result, calls, _, _, errors, _ = self.invoke(("--yes",), [self.response, changed])
        self.assertEqual(result, 1)
        self.assertEqual([call.args[0] for call in calls], ["get", "get"])
        self.assertIn("changed since preview", errors)

    def test_verification_mismatch_is_failure(self):
        empty = self.response_for({**self.payload, "reservationData": []})
        result, calls, _, _, errors, _ = self.invoke(
            ("--yes",), [self.response, self.response, {"success": True}, empty],
        )
        self.assertEqual(result, 1)
        self.assertEqual(calls[-1].args[0], "get")
        self.assertIn("Verification mismatch", errors)

    def test_api_failures_stop_workflow(self):
        for responses, methods in (
            ([subprocess.CalledProcessError(1, "synowebapi")], ["get"]),
            ([self.response, self.response, ValueError("write failed")], ["get", "get", "set"]),
            ([self.response, self.response, {"success": True}, ValueError("read failed")],
             ["get", "get", "set", "get"]),
        ):
            result, calls, _, _, errors, _ = self.invoke(("--yes",), responses)
            self.assertEqual(result, 1)
            self.assertEqual([call.args[0] for call in calls], methods)
            self.assertIn("Error:", errors)

    def test_new_ipv6_reservations_prevent_write_after_confirmation(self):
        changed = copy.deepcopy(self.response)
        changed["data"]["reservationList"]["ipv6"] = [{"ip": "2001:db8::1"}]
        result, calls, _, _, errors, _ = self.invoke(("--yes",), [self.response, changed])
        self.assertEqual(result, 1)
        self.assertEqual([call.args[0] for call in calls], ["get", "get"])
        self.assertIn("IPv6", errors)

    def test_empty_export_is_explicit_full_list_deletion(self):
        self.payload["reservationData"] = []
        verified = self.response_for(self.payload)
        result, calls, _, output, errors, _ = self.invoke(
            ("--yes",), [self.response, self.response, {"success": True}, verified],
        )
        self.assertEqual(result, 0, errors)
        self.assertEqual(calls[2].args, ("set", "bond0", []))
        self.assertIn("1 current -> 0 intended", output)

    def test_ipv6_prevents_writes(self):
        self.response["data"]["reservationList"]["ipv6"] = [{"ip": "2001:db8::1"}]
        result, calls, _, _, errors, backups = self.invoke(("--yes",))
        self.assertEqual(result, 1)
        self.assertEqual(len(calls), 1)
        self.assertEqual(backups, 0)
        self.assertIn("IPv6", errors)

    def test_comparison_ignores_order_and_mac_case(self):
        second = {"mac": "02:00:00:00:00:01", "ip": "10.24.17.1", "hostname": "beta"}
        self.payload["reservationData"].append(second)
        reordered = self.response_for({
            **self.payload, "reservationData": list(reversed(self.payload["reservationData"])),
        })
        reordered["data"]["reservationList"]["ipv4"][1]["clid"] = "02:AA:BB:CC:DD:EE"
        self.assertEqual(
            dsm_apply.canonical_lines(dsm_apply.current_payload(reordered, "bond0")),
            dsm_apply.canonical_lines(self.payload),
        )
