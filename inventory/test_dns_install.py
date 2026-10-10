import copy
import fcntl
import hashlib
from io import StringIO
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from synology import dns_install as installer


class DNSInstallTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="dns-install-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.paths = {}
        for name in ("inbox", "outbox", "destination", "state"):
            self.paths[name] = self.root / name
            self.paths[name].mkdir(mode=0o700)
        self.paths["inbox"].chmod(0o777)
        self.validator = self.root / "named-checkzone"
        self.validator.write_text("#!/bin/sh\nexit 0\n")
        self.validator.chmod(0o700)
        self.config_path = self.root / "installer.ini"
        self.config_path.write_text(
            "[dns_install]\n"
            + "".join(f"{name}_directory = {path}\n" for name, path in (
                ("inbox", self.paths["inbox"]), ("outbox", self.paths["outbox"]),
                ("destination", self.paths["destination"]), ("state", self.paths["state"])))
            + f"allowed_zones = example.net, 17.24.10.in-addr.arpa\nnamed_checkzone = {self.validator}\n"
        )
        self.config_path.chmod(0o600)
        self.script = self.root / "protected-installer.py"
        self.script.write_bytes(Path(installer.__file__).read_bytes())
        self.script.chmod(0o700)
        self.config = installer.load_config(self.config_path)
        self.serial = 2026100801
        self.names = {"example.net", "17.24.10.in-addr.arpa"}
        self.delivery = f"dnsgrid-{self.serial}-" + "a" * 32
        self.publish()

    def zone(self, serial, extra=""):
        return (
            "$ORIGIN example.net.\n$TTL 3600\n"
            "@ IN SOA ns.example.net. hostmaster.example.net. (\n"
            f" {serial} ; serial\n3600 600 86400 60 )\n"
            "@ IN NS ns.example.net.\n" + extra
        ).encode("ascii")

    def publish(self, serial=None, suffix="a", extra=""):
        serial = self.serial if serial is None else serial
        delivery = f"dnsgrid-{serial}-" + suffix * 32
        directory = self.paths["inbox"] / delivery
        directory.mkdir(exist_ok=True)
        entries = []
        for name in sorted(self.names):
            data = self.zone(serial, extra)
            (directory / name).write_bytes(data)
            entries.append({"name": name, "filename": name, "size": len(data),
                            "sha256": hashlib.sha256(data).hexdigest()})
        manifest = {"version": 1, "generation": f"dnsgrid-{serial}", "serial": serial,
                    "published_at": "2026-10-08T13:00:00+00:00", "zones": entries}
        (directory / "manifest.json").write_text(json.dumps(manifest))
        return directory

    def invoke(self, dry_run=False):
        with patch("sys.stderr", StringIO()), patch.object(installer, "__file__", str(self.script)):
            return installer.main(["--config", str(self.config_path)]
                                  + (["--dry-run"] if dry_run else []))

    def result(self, delivery=None):
        return json.loads((self.paths["outbox"] / ((delivery or self.delivery) + ".json")).read_text())

    def assert_empty_install(self):
        self.assertEqual(list(self.paths["destination"].iterdir()), [])
        self.assertFalse((self.paths["state"] / installer.STATE_NAME).exists())

    def edit_manifest(self, mutate):
        path = self.paths["inbox"] / self.delivery / "manifest.json"
        manifest = json.loads(path.read_text())
        mutate(manifest)
        path.write_text(json.dumps(manifest))

    def test_install_result_and_canonical_retry(self):
        self.assertEqual(self.invoke(), 0)
        self.assertEqual(self.result()["status"], "installed")
        self.assertEqual(self.result()["delivery"], self.delivery)
        self.assertEqual(self.result()["serial"], self.serial)
        self.assertTrue(self.result()["timestamp"].endswith("+00:00"))
        for name in self.names:
            self.assertEqual((self.paths["destination"] / name).read_bytes(), self.zone(self.serial))
        self.assertEqual(stat.S_IMODE((self.paths["outbox"] / (self.delivery + ".json")).stat().st_mode), 0o644)
        self.edit_manifest(lambda m: m["zones"].reverse())
        self.edit_manifest(lambda m: m.update(published_at="2026-10-09T13:00:00Z"))
        self.assertEqual(self.invoke(), 0)
        self.assertEqual(self.result()["status"], "installed")
        (self.paths["outbox"] / (self.delivery + ".json")).unlink()
        self.assertEqual(self.invoke(), 0)
        self.assertEqual(self.result()["status"], "already_installed")

    def test_partial_and_invalid_names_ignored(self):
        source = self.paths["inbox"] / self.delivery
        source.rename(source.with_name(self.delivery + ".partial"))
        (self.paths["inbox"] / "dnsgrid-malicious").mkdir()
        self.assertEqual(self.invoke(), 0)
        self.assert_empty_install()
        self.assertEqual(list(self.paths["outbox"].iterdir()), [])

    def test_dry_run_checks_every_zone_without_persistent_changes(self):
        with patch.object(installer, "check_zone", wraps=installer.check_zone) as check:
            self.assertEqual(self.invoke(True), 0)
            self.assertEqual(check.call_count, 2)
        self.assert_empty_install()
        self.assertEqual(list(self.paths["outbox"].iterdir()), [])
        self.assertEqual({p.name for p in self.paths["state"].iterdir()}, {installer.LOCK_NAME})
        self.assertEqual(self.invoke(), 0)
        before = {p.name: p.read_bytes() for p in self.paths["state"].iterdir() if p.is_file()}
        result_before = (self.paths["outbox"] / (self.delivery + ".json")).read_bytes()
        self.assertEqual(self.invoke(True), 0)
        self.assertEqual(before, {p.name: p.read_bytes() for p in self.paths["state"].iterdir() if p.is_file()})
        self.assertEqual(result_before, (self.paths["outbox"] / (self.delivery + ".json")).read_bytes())

    def test_lower_and_equal_collision(self):
        self.assertEqual(self.invoke(), 0)
        lower = self.publish(self.serial - 1, "b")
        collision = self.publish(self.serial, "c", 'text IN TXT "different"\n')
        self.assertEqual(self.invoke(), 5)
        for directory in (lower, collision):
            self.assertEqual(self.result(directory.name)["status"], "failed")
        for name in self.names:
            self.assertEqual((self.paths["destination"] / name).read_bytes(), self.zone(self.serial))

    def test_initial_baseline_rejects_preexisting_higher_or_equal_different(self):
        existing = self.paths["destination"] / "example.net"
        for data in (self.zone(self.serial + 1), self.zone(self.serial, 'text IN TXT "existing"\n')):
            existing.write_bytes(data)
            existing.chmod(0o644)
            self.assertEqual(self.invoke(), 5)
            self.assertEqual(existing.read_bytes(), data)
            self.assertFalse((self.paths["state"] / installer.STATE_NAME).exists())
        existing.write_bytes(self.zone(self.serial))
        self.assertEqual(self.invoke(), 0)

    def test_initial_baseline_mixed_serials_uses_highest_and_equal_content(self):
        names = sorted(self.names)
        for name, serial in zip(names, (self.serial - 1, self.serial + 1)):
            path = self.paths["destination"] / name
            path.write_bytes(self.zone(serial))
            path.chmod(0o644)
        self.assertEqual(self.invoke(), 5)
        path = self.paths["destination"] / names[1]
        path.write_bytes(self.zone(self.serial))
        self.assertEqual(self.invoke(), 0)

    def test_same_content_new_delivery_already_installed(self):
        self.assertEqual(self.invoke(), 0)
        delivery = self.publish(suffix="b")
        self.assertEqual(self.invoke(), 0)
        self.assertEqual(self.result(delivery.name)["status"], "already_installed")

    def test_completed_older_delivery_keeps_success_after_newer_install(self):
        self.assertEqual(self.invoke(), 0)
        receipt = (self.paths["outbox"] / (self.delivery + ".json")).read_bytes()
        newer = self.publish(self.serial + 1, "b")
        self.assertEqual(self.invoke(), 0)
        self.assertEqual(self.result(newer.name)["status"], "installed")
        with patch.object(installer, "snapshot") as snapshot:
            self.assertEqual(self.invoke(), 0)
            snapshot.assert_not_called()
        self.assertEqual((self.paths["outbox"] / (self.delivery + ".json")).read_bytes(), receipt)
        self.assertEqual(self.result()["status"], "installed")

    def test_failed_receipt_retried_and_successful_receipt_preserved(self):
        self.validator.write_text("#!/bin/sh\nexit 1\n")
        self.assertEqual(self.invoke(), 5)
        self.assertEqual(self.result()["status"], "failed")
        self.validator.write_text("#!/bin/sh\nexit 0\n")
        self.assertEqual(self.invoke(), 0)
        self.assertEqual(self.result()["status"], "installed")
        self.assertEqual(self.invoke(), 0)
        self.assertEqual(self.result()["status"], "installed")

    def test_spoofed_writable_or_symlink_receipt_cannot_skip_validation(self):
        path = self.paths["outbox"] / (self.delivery + ".json")
        fake = {"delivery": self.delivery, "serial": self.serial, "status": "installed",
                "timestamp": "2026-10-08T12:00:00Z", "summary": "Spoof"}
        path.write_text(json.dumps(fake))
        path.chmod(0o666)
        self.assertNotEqual(self.invoke(), 0)
        self.assertEqual(self.result()["status"], "failed")
        self.assert_empty_install()
        path.unlink()
        target = self.root / "spoof"
        target.write_text(json.dumps(fake))
        target.chmod(0o644)
        path.symlink_to(target)
        self.assertNotEqual(self.invoke(), 0)
        self.assertFalse(path.is_symlink())
        self.assertEqual(self.result()["status"], "failed")
        self.assert_empty_install()
        self.assertEqual(self.invoke(), 0)

    def test_manifest_hostile_variants(self):
        original = (self.paths["inbox"] / self.delivery / "manifest.json").read_bytes()
        mutations = [
            lambda m: m.update(serial=True),
            lambda m: m.update(version=True),
            lambda m: m.update(version=2),
            lambda m: m.update(generation="dnsgrid-2026100802"),
            lambda m: m.update(published_at="2026-02-30T12:00:00Z"),
            lambda m: m.update(published_at="2026-10-08T12:00:00+01:00"),
            lambda m: m.update(extra="hostile"),
            lambda m: m["zones"][0].update(filename="../escape"),
            lambda m: m["zones"][0].update(name="../../escape"),
            lambda m: m["zones"][0].update(size=True),
            lambda m: m["zones"][0].update(size=installer.MAX_ZONE + 1),
            lambda m: m["zones"][0].update(sha256="A" * 64),
            lambda m: m["zones"].pop(),
            lambda m: m["zones"].append(copy.deepcopy(m["zones"][0])),
        ]
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                (self.paths["inbox"] / self.delivery / "manifest.json").write_bytes(original)
                self.edit_manifest(mutation)
                self.assertEqual(self.invoke(), 5)
                self.assertEqual(self.result()["status"], "failed")
                self.assert_empty_install()

    def test_manifest_duplicate_json_key_and_bounds(self):
        path = self.paths["inbox"] / self.delivery / "manifest.json"
        for data in (b'{"version":1,"version":1}', b" " * (installer.MAX_MANIFEST + 1),
                     b"\xff", b"[" * 2000):
            path.write_bytes(data)
            self.assertEqual(self.invoke(), 5)
            self.assert_empty_install()

    def test_calendar_serial_and_delivery_syntax(self):
        for value in ("2026022900", "2026130100", "2026103200", "4295010100", "0001010100"):
            with self.assertRaises(installer.InstallError):
                installer.serial_value(value)
        for value in ("2024022900", "2026100800", "2026100899"):
            self.assertEqual(installer.serial_value(value), int(value))
        self.assertIsNone(installer.DELIVERY.fullmatch(self.delivery.upper()))
        self.assertIsNone(installer.DELIVERY.fullmatch(self.delivery + "\n"))

    def test_unexpected_file_and_nested_directory(self):
        directory = self.paths["inbox"] / self.delivery
        (directory / "extra").write_text("unexpected")
        self.assertEqual(self.invoke(), 5)
        (directory / "extra").unlink()
        (directory / "extra").mkdir()
        self.assertEqual(self.invoke(), 5)
        self.assert_empty_install()

    def test_symlink_delivery_manifest_zone_and_hardlink(self):
        directory = self.paths["inbox"] / self.delivery
        for name in ("manifest.json", "example.net"):
            path = directory / name
            saved = self.root / ("saved-" + name)
            path.rename(saved)
            path.symlink_to(saved)
            self.assertNotEqual(self.invoke(), 0)
            path.unlink()
            saved.rename(path)
        path = directory / "example.net"
        os.link(path, self.root / "hardlink")
        self.assertNotEqual(self.invoke(), 0)
        (self.root / "hardlink").unlink()
        saved = self.root / "delivery"
        directory.rename(saved)
        directory.symlink_to(saved, target_is_directory=True)
        self.assertNotEqual(self.invoke(), 0)
        self.assert_empty_install()

    def test_fifo_and_oversized_zone_rejected_without_blocking(self):
        path = self.paths["inbox"] / self.delivery / "example.net"
        path.unlink()
        os.mkfifo(path)
        self.assertNotEqual(self.invoke(), 0)
        path.unlink()
        with path.open("wb") as stream:
            stream.truncate(installer.MAX_ZONE + 1)
        self.assertNotEqual(self.invoke(), 0)
        self.assert_empty_install()

    def test_soa_serial_comments_txt_and_external_directives(self):
        self.assertEqual(installer.soa_serial(self.zone(self.serial, '; SOA fake fake 0\n')), self.serial)
        self.assertEqual(installer.soa_serial(self.zone(self.serial, 'text IN TXT SOA\n')), self.serial)
        for data in (
                self.zone(self.serial - 1), self.zone(self.serial, self.zone(self.serial).decode()),
                self.zone(self.serial, '$INCLUDE "/etc/shadow"\n'),
                b'@ IN TXT "SOA ns. host. 2026100801 1 2 3 4"\n'):
            with self.subTest(data=data):
                if data == self.zone(self.serial - 1):
                    directory = self.paths["inbox"] / self.delivery
                    (directory / "example.net").write_bytes(data)
                    self.edit_manifest(lambda m: next(z for z in m["zones"] if z["name"] == "example.net").update(
                        size=len(data), sha256=hashlib.sha256(data).hexdigest()))
                    self.assertEqual(self.invoke(), 5)
                else:
                    with self.assertRaises(installer.InstallError):
                        installer.soa_serial(data)

    def test_checkzone_absent_failed_timeout_output_not_leaked(self):
        self.validator.unlink()
        self.assertNotEqual(self.invoke(), 0)
        self.assertEqual(self.result()["status"], "failed")
        self.validator.write_text("#!/bin/sh\necho 'secret-hostile-error' >&2\nexit 1\n")
        self.validator.chmod(0o700)
        self.assertEqual(self.invoke(), 5)
        self.assertNotIn("secret", self.result()["summary"])
        with patch.object(installer.subprocess, "run", side_effect=subprocess.TimeoutExpired("check", 1)):
            self.assertEqual(self.invoke(), 5)
        self.assert_empty_install()

    def test_validator_arguments_private_snapshot_no_shell(self):
        original = subprocess.run
        calls = []
        def checked(args, **kwargs):
            calls.append((args, kwargs))
            self.assertEqual(Path(args[2]).parent.parent, self.paths["state"])
            self.assertEqual(stat.S_IMODE(Path(args[2]).parent.stat().st_mode), 0o700)
            return original(args, **kwargs)
        with patch.object(installer.subprocess, "run", side_effect=checked):
            self.assertEqual(self.invoke(), 0)
        self.assertEqual(len(calls), 2)
        for args, kwargs in calls:
            self.assertFalse(kwargs["shell"])
            self.assertEqual(kwargs["stdout"], subprocess.DEVNULL)
            self.assertEqual(kwargs["stderr"], subprocess.DEVNULL)
            self.assertEqual(kwargs["timeout"], installer.TIMEOUT)

    def test_rename_delivery_while_descriptor_is_open(self):
        original = installer.read_file
        moved = False
        def mutate(fd, name, *args, **kwargs):
            nonlocal moved
            data = original(fd, name, *args, **kwargs)
            if name == "manifest.json" and not moved:
                moved = True
                directory = self.paths["inbox"] / self.delivery
                directory.rename(self.root / "old-delivery")
                directory.mkdir()
                (directory / "manifest.json").write_text("malicious")
            return data
        with patch.object(installer, "read_file", side_effect=mutate):
            self.assertEqual(self.invoke(), 0)
        self.assertEqual(self.result()["status"], "installed")

    def test_mutation_after_copy_cannot_change_validation_or_install(self):
        original = installer.check_zone
        def mutate(config, name, path, stage):
            (self.paths["inbox"] / self.delivery / name).write_bytes(b"hostile concurrent replacement")
            return original(config, name, path, stage)
        with patch.object(installer, "check_zone", side_effect=mutate):
            self.assertEqual(self.invoke(), 0)
        for name in self.names:
            self.assertEqual((self.paths["destination"] / name).read_bytes(), self.zone(self.serial))

    def test_inplace_mutation_during_read_rejected(self):
        original = os.fstat
        mutated = False
        def mutate(fd):
            nonlocal mutated
            info = original(fd)
            path = self.paths["inbox"] / self.delivery / "example.net"
            if info.st_ino == path.stat().st_ino and not mutated:
                mutated = True
                path.write_bytes(b"mutated")
            return info
        with patch.object(installer.os, "fstat", side_effect=mutate):
            self.assertEqual(self.invoke(), 5)
        self.assert_empty_install()

    def test_protected_directories_config_script_and_ancestors(self):
        for name in ("state", "outbox", "destination"):
            self.paths[name].chmod(0o777)
            self.assertEqual(self.invoke(), 2)
            self.paths[name].chmod(0o700)
        self.config_path.chmod(0o666)
        self.assertNotEqual(self.invoke(), 0)
        self.config_path.chmod(0o600)
        self.script.chmod(0o777)
        self.assertNotEqual(self.invoke(), 0)
        self.script.chmod(0o700)
        self.root.chmod(0o777)
        self.assertNotEqual(self.invoke(), 0)
        self.root.chmod(0o700)
        saved = self.paths["outbox"].with_name("real-outbox")
        self.paths["outbox"].rename(saved)
        self.paths["outbox"].symlink_to(saved)
        self.assertNotEqual(self.invoke(), 0)
        self.assert_empty_install()

    def test_outbox_cannot_be_under_sftp_writable_parent(self):
        bad = self.paths["inbox"] / "outbox"
        bad.mkdir(mode=0o700)
        config = dict(self.config, outbox_directory=bad)
        with self.assertRaises(installer.InstallError):
            installer.run(config)

    def test_root_owned_sticky_intermediate_only(self):
        shared = self.root / "shared"
        shared.mkdir(mode=0o700)
        private = shared / "private"
        private.mkdir(mode=0o700)
        shared.chmod(0o1777)
        original = installer.os.fstat
        def root_owned_sticky(fd):
            info = original(fd)
            if info.st_ino == shared.stat().st_ino:
                values = list(info)
                values[4] = 0
                return os.stat_result(values)
            return info
        with patch.object(installer.os, "fstat", side_effect=root_owned_sticky):
            fd = installer.open_directory(private)
            os.close(fd)
            with self.assertRaises(installer.InstallError):
                installer.open_directory(shared)
            shared.chmod(0o777)
            with self.assertRaises(installer.InstallError):
                installer.open_directory(private)
        shared.chmod(0o700)

    def test_large_validator_is_checked_by_metadata_not_size(self):
        with self.validator.open("ab") as stream:
            stream.write(b"#" + b"x" * (installer.MAX_MANIFEST + 1) + b"\n")
        self.assertEqual(self.invoke(), 0)

    def test_lock_nonblocking_and_hostile_lock(self):
        lock_path = self.paths["state"] / installer.LOCK_NAME
        with lock_path.open("wb") as lock:
            lock_path.chmod(0o600)
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.assertEqual(self.invoke(), 3)
            self.assertEqual(self.invoke(True), 3)
        lock_path.unlink()
        lock_path.symlink_to(self.config_path)
        self.assertNotEqual(self.invoke(), 0)
        self.assert_empty_install()

    def test_rollback_restores_old_and_removes_initially_absent_files(self):
        name = sorted(self.names)[0]
        existing = self.paths["destination"] / name
        existing.write_bytes(self.zone(self.serial - 1))
        existing.chmod(0o640)
        unrelated = self.paths["destination"] / "unrelated"
        unrelated.write_text("keep")
        original = installer.atomic_write
        failed = False
        def fail(fd, filename, data, mode=0o600):
            nonlocal failed
            if filename == installer.STATE_NAME and not failed:
                failed = True
                raise OSError("hostile leaked message")
            return original(fd, filename, data, mode)
        with patch.object(installer, "atomic_write", side_effect=fail):
            self.assertEqual(self.invoke(), 6)
        self.assertEqual(existing.read_bytes(), self.zone(self.serial - 1))
        self.assertEqual(stat.S_IMODE(existing.stat().st_mode), 0o640)
        self.assertFalse((self.paths["destination"] / sorted(self.names)[1]).exists())
        self.assertEqual(unrelated.read_text(), "keep")
        self.assertFalse((self.paths["state"] / installer.JOURNAL_NAME).exists())
        self.assertNotIn("hostile", self.result()["summary"])
        for backup in self.paths["state"].glob("backup-*"):
            self.assertEqual(stat.S_IMODE(backup.stat().st_mode), 0o700)

    def test_rollback_failure_retains_journal_blocks_until_recovered(self):
        for name in self.names:
            (self.paths["destination"] / name).write_bytes(self.zone(self.serial - 1))
            (self.paths["destination"] / name).chmod(0o644)
        original = installer.atomic_write
        fail_recovery = False
        def fail(fd, filename, data, mode=0o600):
            nonlocal fail_recovery
            if filename == installer.STATE_NAME:
                fail_recovery = True
                raise OSError("install failed")
            if fail_recovery and filename in self.names:
                raise OSError("rollback failed")
            return original(fd, filename, data, mode)
        with patch.object(installer, "atomic_write", side_effect=fail):
            self.assertEqual(self.invoke(), 7)
        self.assertTrue((self.paths["state"] / installer.JOURNAL_NAME).exists())
        self.assertEqual(self.result()["status"], "failed")
        self.assertEqual(self.invoke(True), 7)
        with patch.object(installer, "atomic_write", side_effect=fail):
            with patch.object(installer, "snapshot") as snapshot:
                self.assertEqual(self.invoke(), 7)
                snapshot.assert_not_called()
        self.assertEqual(self.invoke(), 0)
        self.assertFalse((self.paths["state"] / installer.JOURNAL_NAME).exists())

    def test_durable_journal_exists_before_first_replacement_and_crash_recovery(self):
        for name in self.names:
            (self.paths["destination"] / name).write_bytes(self.zone(self.serial - 1))
            (self.paths["destination"] / name).chmod(0o644)
        original = installer.atomic_write
        def crash(fd, filename, data, mode=0o600):
            if filename in self.names and data == self.zone(self.serial):
                self.assertTrue((self.paths["state"] / installer.JOURNAL_NAME).exists())
                original(fd, filename, data, mode)
                raise KeyboardInterrupt()
            return original(fd, filename, data, mode)
        with patch.object(installer, "atomic_write", side_effect=crash):
            with self.assertRaises(KeyboardInterrupt):
                self.invoke()
        source = self.paths["inbox"] / self.delivery
        source.rename(source.with_name(self.delivery + ".partial"))
        self.assertEqual(self.invoke(), 0)
        for name in self.names:
            self.assertEqual((self.paths["destination"] / name).read_bytes(), self.zone(self.serial - 1))
        self.assertFalse((self.paths["state"] / installer.STATE_NAME).exists())

    def test_journal_unlink_fsync_failure_still_rolls_back(self):
        original = installer.os.fsync
        failed = False
        def fail(fd):
            nonlocal failed
            state_path = self.paths["state"]
            if (not failed and os.fstat(fd).st_ino == state_path.stat().st_ino
                    and (state_path / installer.STATE_NAME).exists()
                    and not (state_path / installer.JOURNAL_NAME).exists()):
                failed = True
                raise OSError("directory flush failure")
            return original(fd)
        with patch.object(installer.os, "fsync", side_effect=fail):
            self.assertEqual(self.invoke(), 6)
        self.assertTrue(failed)
        self.assert_empty_install()
        self.assertFalse((self.paths["state"] / installer.JOURNAL_NAME).exists())

    def test_success_receipt_write_failure_does_not_report_failed_install(self):
        original = installer.result
        calls = []
        def fail_once(outbox, delivery, serial, status, summary):
            calls.append(status)
            if len(calls) == 1:
                raise OSError("outbox unavailable")
            return original(outbox, delivery, serial, status, summary)
        with patch.object(installer, "result", side_effect=fail_once):
            self.assertEqual(self.invoke(), 2)
        self.assertEqual(calls, ["installed"])
        self.assertEqual(list(self.paths["outbox"].iterdir()), [])
        self.assertTrue((self.paths["state"] / installer.STATE_NAME).exists())
        self.assertFalse((self.paths["state"] / installer.JOURNAL_NAME).exists())
        for name in self.names:
            self.assertEqual((self.paths["destination"] / name).read_bytes(), self.zone(self.serial))
        self.assertEqual(self.invoke(), 0)
        self.assertEqual(self.result()["status"], "already_installed")

    def test_copied_script_help_and_real_install_is_stdlib_only(self):
        copied = self.root / "dns_install.py"
        copied.write_bytes(Path(installer.__file__).read_bytes())
        copied.chmod(0o700)
        for args in (["--help"], ["--config", str(self.config_path), "--dry-run"],
                     ["--config", str(self.config_path)]):
            process = subprocess.run([sys.executable, "-I", "-S", str(copied), *args],
                                     cwd=self.root, capture_output=True, text=True, timeout=15)
            self.assertEqual(process.returncode, 0, process.stderr)
        self.assertEqual(self.result()["status"], "installed")


if __name__ == "__main__":
    unittest.main()
