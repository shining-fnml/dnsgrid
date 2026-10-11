import copy
import fcntl
import hashlib
from io import StringIO
import json
import os
from pathlib import Path
import pwd
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace

from synology import dns_install as installer


class DNSInstallTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="dns-install-test-", dir=Path.cwd())
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

    def configure_package(self, owner=None):
        package = self.root / "package"
        package.mkdir(mode=0o755)
        self.paths["destination"].rename(package / "master")
        self.paths["destination"] = package / "master"
        self.validator.rename(package / "named-checkzone")
        self.validator = package / "named-checkzone"
        account = pwd.getpwnam(owner) if owner else pwd.getpwuid(os.geteuid())
        self.package_identity = (account.pw_uid, account.pw_gid)
        text = self.config_path.read_text()
        text = text.replace(str(self.root / "destination"), str(self.paths["destination"]))
        text = text.replace(str(self.root / "named-checkzone"), str(self.validator))
        self.config_path.write_text(
            text + f"package_root = {package}\npackage_owner = {account.pw_name}\n")
        self.config = installer.load_config(self.config_path)
        return package

    def test_package_configuration_requires_account_and_bounded_root(self):
        package = self.configure_package()
        self.assertEqual(self.config["package_identity"], self.package_identity)
        valid = self.config_path.read_text()
        for text in (
            valid.replace(f"package_owner = {self.config['package_owner']}",
                          "package_owner = dnsgrid-nonexistent-account"),
            valid.replace(f"package_root = {package}", f"package_root = {package / 'other'}"),
            valid.replace(f"package_root = {package}", f"package_root = {self.root}"),
            valid.replace(f"package_root = {package}\n", ""),
        ):
            with self.subTest(text=text):
                self.config_path.write_text(text)
                with self.assertRaises(installer.InstallError):
                    installer.load_config(self.config_path)

    def test_package_directory_trust_is_scoped_and_rejects_unsafe_metadata(self):
        package = self.configure_package()
        account = pwd.getpwnam("nobody")
        self.package_identity = (account.pw_uid, account.pw_gid)
        self.config["package_identity"] = self.package_identity
        original = installer.os.fstat
        inodes = {path.stat().st_ino for path in (package, self.paths["destination"])}
        def package_owned(fd):
            info = original(fd)
            if info.st_ino in inodes:
                values = list(info)
                values[4], values[5] = self.package_identity
                return os.stat_result(values)
            return info
        with patch.object(installer.os, "fstat", side_effect=package_owned):
            fd = installer.open_directory(self.paths["destination"], config=self.config)
            os.close(fd)
            with self.assertRaisesRegex(installer.InstallError, r"package.*uid=.*gid=.*mode=0755"):
                installer.open_directory(self.paths["destination"])
            for mode in (0o775, 0o777, 0o1777):
                package.chmod(mode)
                with self.assertRaises(installer.InstallError):
                    installer.open_directory(self.paths["destination"], config=self.config)
        package.chmod(0o755)
        self.package_identity = (self.package_identity[0] + 1, self.package_identity[1])
        with patch.object(installer.os, "fstat", side_effect=package_owned):
            with self.assertRaises(installer.InstallError):
                installer.open_directory(self.paths["destination"], config=self.config)

    def test_package_directory_and_validator_symlinks_rejected(self):
        package = self.configure_package()
        real = package.with_name("real-package")
        package.rename(real)
        package.symlink_to(real)
        self.assertEqual(self.invoke(), 2)
        package.unlink()
        real.rename(package)
        saved = self.validator.with_name("real-validator")
        self.validator.rename(saved)
        self.validator.symlink_to(saved)
        self.assertEqual(self.invoke(), 5)
        self.assert_empty_install()

    def test_package_zone_metadata_policy(self):
        self.configure_package()
        zone = self.paths["destination"] / sorted(self.names)[0]
        zone.write_bytes(self.zone(self.serial - 1))
        zone.chmod(0o666)
        original = installer.os.fstat
        inode = zone.stat().st_ino
        uid, gid = self.package_identity
        def metadata(fd):
            info = original(fd)
            if info.st_ino == inode:
                return SimpleNamespace(
                    st_uid=uid, st_gid=gid, st_mode=info.st_mode, st_nlink=info.st_nlink,
                    st_size=info.st_size, st_mtime_ns=info.st_mtime_ns, st_ctime_ns=info.st_ctime_ns)
            return info
        with patch.object(installer.os, "fstat", side_effect=metadata):
            self.assertEqual(self.invoke(True), 0)
            uid += 1
            self.assertEqual(self.invoke(True), 5)
        zone.unlink()
        zone.symlink_to(self.config_path)
        self.assertEqual(self.invoke(True), 5)
        zone.unlink()
        zone.mkdir()
        self.assertEqual(self.invoke(True), 5)
        zone.rmdir()
        zone.write_bytes(self.zone(self.serial - 1))
        zone.chmod(0o644)
        os.link(zone, self.root / "hardlink")
        self.assertEqual(self.invoke(True), 5)

    def test_package_validator_unexpected_owner_and_write_bits_rejected(self):
        self.configure_package()
        original = installer.os.fstat
        inode = self.validator.stat().st_ino
        def unexpected_owner(fd):
            info = original(fd)
            if info.st_ino == inode:
                values = list(info)
                values[4] = self.package_identity[0] + 1
                return os.stat_result(values)
            return info
        with patch.object(installer.os, "fstat", side_effect=unexpected_owner):
            self.assertEqual(self.invoke(True), 5)
        self.validator.chmod(0o775)
        self.assertEqual(self.invoke(True), 5)
        self.assert_empty_install()

    @unittest.skipUnless(os.geteuid() == 0, "Real package ownership requires root")
    def test_real_package_install_normalizes_and_leaves_other_zones_untouched(self):
        package = self.configure_package("nobody")
        for path in (package, self.paths["destination"], self.validator):
            os.chown(path, *self.package_identity)
            path.chmod(0o755)
        for name in sorted(self.names)[:1]:
            path = self.paths["destination"] / name
            path.write_bytes(self.zone(self.serial - 1))
            os.chown(path, *self.package_identity)
            path.chmod(0o666)
        unrelated = self.paths["destination"] / "unconfigured.zone"
        unrelated.write_bytes(b"must not be read")
        os.chown(unrelated, *self.package_identity)
        unrelated.chmod(0o000)
        before = unrelated.stat()
        (self.paths["destination"] / "@eaDir").mkdir()
        (self.paths["destination"] / "unconfigured-link").symlink_to(self.config_path)
        self.assertEqual(self.invoke(), 0)
        for name in self.names:
            info = (self.paths["destination"] / name).stat()
            self.assertEqual((info.st_uid, info.st_gid), self.package_identity)
            self.assertEqual(stat.S_IMODE(info.st_mode), 0o644)
        self.assertEqual(unrelated.stat(), before)
        self.assertEqual(unrelated.read_bytes(), b"must not be read")
        self.assertTrue((self.paths["destination"] / "@eaDir").is_dir())
        for path in (self.paths["outbox"], self.paths["state"]):
            os.chown(path, *self.package_identity)
            self.assertEqual(self.invoke(), 2)
            os.chown(path, 0, 0)

    @unittest.skipUnless(os.geteuid() == 0, "Real package ownership requires root")
    def test_real_package_crash_rollback_restores_exact_metadata(self):
        package = self.configure_package("nobody")
        for path in (package, self.paths["destination"], self.validator):
            os.chown(path, *self.package_identity)
            path.chmod(0o755)
        originals = {}
        for index, name in enumerate(sorted(self.names)):
            path = self.paths["destination"] / name
            path.write_bytes(self.zone(self.serial - 1))
            os.chown(path, self.package_identity[0], self.package_identity[1] + index)
            path.chmod(0o666 if index else 0o640)
            originals[name] = path.stat()
        original = installer.atomic_write
        def crash(fd, filename, data, mode=0o600, **kwargs):
            original(fd, filename, data, mode, **kwargs)
            if filename == installer.STATE_NAME:
                raise KeyboardInterrupt()
        with patch.object(installer, "atomic_write", side_effect=crash):
            with self.assertRaises(KeyboardInterrupt):
                self.invoke()
        journal = json.loads((self.paths["state"] / installer.JOURNAL_NAME).read_bytes())
        self.assertEqual(journal["version"], 2)
        source = self.paths["inbox"] / self.delivery
        source.rename(source.with_name(self.delivery + ".partial"))
        self.assertEqual(self.invoke(), 0)
        for name, before in originals.items():
            path = self.paths["destination"] / name
            after = path.stat()
            self.assertEqual((after.st_uid, after.st_gid, after.st_mode),
                             (before.st_uid, before.st_gid, before.st_mode))
            self.assertEqual(path.read_bytes(), self.zone(self.serial - 1))

    def test_legacy_and_unconfigured_zone_journals_block_without_modification(self):
        state = self.paths["state"] / installer.JOURNAL_NAME
        state.write_text(json.dumps({"backup": "backup-" + "a" * 32, "entries": [],
                                     "previous_state": None}))
        state.chmod(0o600)
        self.assertEqual(self.invoke(), 7)
        self.assert_empty_install()
        entry = {"name": "unconfigured.zone", "present": False, "mode": 0o644,
                 "uid": os.geteuid(), "gid": os.getegid()}
        state.write_text(json.dumps({"version": 2, "backup": "backup-" + "a" * 32,
                                     "entries": [entry], "previous_state": None}))
        unrelated = self.paths["destination"] / entry["name"]
        unrelated.write_text("keep")
        self.assertEqual(self.invoke(), 7)
        self.assertEqual(unrelated.read_text(), "keep")

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

    def test_uint32_serial_and_canonical_delivery_syntax(self):
        for value in ("-1", "4294967296", "9999999999", "10000000000", "", "1.0", "١", True, 0):
            with self.subTest(value=value), self.assertRaisesRegex(installer.InstallError, "uint32"):
                installer.serial_value(value)
        for value in ("0", "1", "1692746706", "2026022900", "2026130100", "2026103200",
                      "4294967295", "0001010100"):
            self.assertEqual(installer.serial_value(value), int(value))
            self.assertEqual(installer.soa_serial(self.zone(value)), int(value))
        for value in ("0", "1", "1692746706", "2026100801", "4294967295"):
            self.assertIsNotNone(installer.DELIVERY.fullmatch(f"dnsgrid-{value}-" + "a" * 32))
        for value in ("00", "01", "0001010100", "-1", "10000000000"):
            self.assertIsNone(installer.DELIVERY.fullmatch(f"dnsgrid-{value}-" + "a" * 32))
        self.assertIsNone(installer.DELIVERY.fullmatch(self.delivery.upper()))
        self.assertIsNone(installer.DELIVERY.fullmatch(self.delivery + "\n"))

    def test_timestamp_serial_initial_baseline(self):
        for name in self.names:
            path = self.paths["destination"] / name
            path.write_bytes(self.zone(1692746706))
            path.chmod(0o644)
        self.assertEqual(self.invoke(), 0)
        self.assertEqual(self.result()["status"], "installed")

    def test_zero_initial_baseline_is_not_missing(self):
        source = self.paths["inbox"] / self.delivery
        source.rename(source.with_name(self.delivery + ".partial"))
        candidate = self.publish(0, "b", 'text IN TXT "changed"\n')
        existing = self.paths["destination"] / "example.net"
        existing.write_bytes(self.zone(0))
        existing.chmod(0o644)
        self.assertEqual(self.invoke(), 5)
        self.assertIn("candidate 0, installed 0", self.result(candidate.name)["summary"])
        self.assertEqual(existing.read_bytes(), self.zone(0))
        self.assertFalse((self.paths["state"] / installer.STATE_NAME).exists())
        candidate.rename(candidate.with_name(candidate.name + ".partial"))
        newer = self.publish(1, "c")
        self.assertEqual(self.invoke(), 0)
        self.assertEqual(self.result(newer.name)["status"], "installed")

    def test_uint32_delivery_bounds_and_invalid_manifest_serials(self):
        source = self.paths["inbox"] / self.delivery
        source.rename(source.with_name(self.delivery + ".partial"))
        for serial in (0, 1, 4294967295, 4294967296):
            with self.subTest(serial=serial):
                delivery = self.publish(serial, "b")
                self.assertEqual(self.invoke(True), 5 if serial > installer.MAX_SERIAL else 0)
                delivery.rename(delivery.with_name(delivery.name + ".partial"))
        manifest = json.loads((source.with_name(self.delivery + ".partial") / "manifest.json").read_text())
        for serial in (-1, 4294967296, True, "0"):
            manifest["serial"] = serial
            with self.subTest(manifest_serial=serial), self.assertRaisesRegex(
                    installer.InstallError, "manifest serial"):
                installer.decode_manifest(json.dumps(manifest).encode(), self.delivery, self.names)
        with self.assertRaisesRegex(installer.InstallError, "delivery serial"):
            installer.decode_manifest(b"{}", "dnsgrid-4294967296-" + "a" * 32, self.names)
        self.assert_empty_install()

    def test_rfc1982_serial_order_and_ambiguity(self):
        for serial, previous, expected in (
                (0, 4294967295, 1), (4294967295, 0, -1), (1, 0, 1),
                (0, 0, 0), (2147483647, 0, 1), (2147483649, 0, -1)):
            self.assertEqual(installer.compare_serial(serial, previous, "test"), expected)
        for serial, previous in ((2147483648, 0), (0, 2147483648)):
            with self.assertRaisesRegex(installer.InstallError, r"Ambiguous RFC 1982.*test"):
                installer.compare_serial(serial, previous, "test")

    def test_initial_baseline_wrap_regression_and_ambiguity_diagnostics(self):
        source = self.paths["inbox"] / self.delivery
        source.rename(source.with_name(self.delivery + ".partial"))
        wrapped = self.publish(0, "b")
        existing = self.paths["destination"] / "example.net"
        for previous, code, message in (
                (4294967295, 0, None), (1, 5, "regression"),
                (2147483648, 5, "Ambiguous RFC 1982")):
            existing.write_bytes(self.zone(previous))
            existing.chmod(0o644)
            with self.subTest(previous=previous):
                self.assertEqual(self.invoke(True), code)
                if message:
                    self.assertEqual(self.invoke(), code)
                    summary = self.result(wrapped.name)["summary"]
                    self.assertIn(message, summary)
                    self.assertIn("example.net", summary)
                    self.assertIn(str(previous), summary)
                    self.assertIn(str(existing), summary)
                self.assertEqual(existing.read_bytes(), self.zone(previous))
                self.assertFalse((self.paths["state"] / installer.STATE_NAME).exists())

    def test_state_wrap_install_idempotence_regression_and_ambiguity(self):
        source = self.paths["inbox"] / self.delivery
        source.rename(source.with_name(self.delivery + ".partial"))
        maximum = self.publish(4294967295, "b")
        self.assertEqual(self.invoke(), 0)
        wrapped = self.publish(0, "c")
        self.assertEqual(self.invoke(), 0)
        self.assertEqual(self.result(wrapped.name)["status"], "installed")
        equal = self.publish(0, "d")
        self.assertEqual(self.invoke(), 0)
        self.assertEqual(self.result(equal.name)["status"], "already_installed")
        rollback = self.publish(4294967295, "e")
        ambiguous = self.publish(2147483648, "f")
        self.assertEqual(self.invoke(), 5)
        self.assertIn("regression", self.result(rollback.name)["summary"])
        self.assertIn("Ambiguous RFC 1982", self.result(ambiguous.name)["summary"])
        self.assertIn("installed.json", self.result(ambiguous.name)["summary"])
        self.assertEqual(self.result(maximum.name)["status"], "installed")
        for name in self.names:
            self.assertEqual((self.paths["destination"] / name).read_bytes(), self.zone(0))
        self.assertEqual(json.loads((self.paths["state"] / installer.STATE_NAME).read_text())["serial"], 0)

    def test_invalid_installer_state_serial_blocks_installation(self):
        state = self.paths["state"] / installer.STATE_NAME
        for serial in (-1, 4294967296, True):
            state.write_text(json.dumps({"serial": serial, "fingerprint": "a" * 64}))
            state.chmod(0o600)
            with self.subTest(serial=serial):
                self.assertEqual(self.invoke(), 7)
                self.assertEqual(list(self.paths["destination"].iterdir()), [])

    def test_failed_wrapped_install_restores_previous_uint32_state(self):
        source = self.paths["inbox"] / self.delivery
        source.rename(source.with_name(self.delivery + ".partial"))
        self.publish(4294967295, "b")
        self.assertEqual(self.invoke(), 0)
        state = self.paths["state"] / installer.STATE_NAME
        previous = state.read_bytes()
        wrapped = self.publish(0, "c")
        original = installer.atomic_write
        failed = False
        def fail(fd, filename, data, mode=0o600, **kwargs):
            nonlocal failed
            if filename == installer.STATE_NAME and not failed:
                failed = True
                raise OSError("simulated state write failure")
            return original(fd, filename, data, mode, **kwargs)
        with patch.object(installer, "atomic_write", side_effect=fail):
            self.assertEqual(self.invoke(), 6)
        self.assertTrue(failed)
        self.assertEqual(state.read_bytes(), previous)
        for name in self.names:
            self.assertEqual((self.paths["destination"] / name).read_bytes(), self.zone(4294967295))
        self.assertEqual(self.result(wrapped.name)["status"], "failed")
        self.assertEqual(self.invoke(), 0)
        self.assertEqual(self.result(wrapped.name)["status"], "installed")

    def test_diagnostics_identify_manifest_zone_path_checksum_and_serial(self):
        directory = self.paths["inbox"] / self.delivery
        original = (directory / "manifest.json").read_bytes()
        for mutation, message in (
                (lambda m: m["zones"][0].update(filename="../escape"), "Invalid filename"),
                (lambda m: m["zones"][0].update(name="../../escape"), "Invalid manifest zone name"),
                (lambda m: m["zones"][0].update(sha256="0" * 64), "checksum mismatch"),
                (lambda m: m["zones"][0].update(size=m["zones"][0]["size"] + 1), "Size mismatch")):
            (directory / "manifest.json").write_bytes(original)
            self.edit_manifest(mutation)
            self.assertEqual(self.invoke(), 5)
            self.assertIn(message, self.result()["summary"])
            self.assertIn(sorted(self.names)[0] if "mismatch" in message else "escape",
                          self.result()["summary"])
        (directory / "manifest.json").write_bytes(original)
        path = directory / "example.net"
        path.write_bytes(self.zone(1692746706))
        self.edit_manifest(lambda m: next(z for z in m["zones"] if z["name"] == path.name).update(
            size=path.stat().st_size, sha256=hashlib.sha256(path.read_bytes()).hexdigest()))
        self.assertEqual(self.invoke(), 5)
        self.assertIn("SOA serial mismatch", self.result()["summary"])
        self.assertIn(str(path), self.result()["summary"])
        self.assertIn("1692746706", self.result()["summary"])
        path.unlink()
        self.assertEqual(self.invoke(), 5)
        self.assertIn("Unexpected or missing files", self.result()["summary"])
        self.assert_empty_install()

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
        def fail(fd, filename, data, mode=0o600, **kwargs):
            nonlocal failed
            if filename == installer.STATE_NAME and not failed:
                failed = True
                raise OSError("hostile leaked message")
            return original(fd, filename, data, mode, **kwargs)
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
        def fail(fd, filename, data, mode=0o600, **kwargs):
            nonlocal fail_recovery
            if filename == installer.STATE_NAME:
                fail_recovery = True
                raise OSError("install failed")
            if fail_recovery and filename in self.names:
                raise OSError("rollback failed")
            return original(fd, filename, data, mode, **kwargs)
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
        def crash(fd, filename, data, mode=0o600, **kwargs):
            if filename in self.names and data == self.zone(self.serial):
                self.assertTrue((self.paths["state"] / installer.JOURNAL_NAME).exists())
                original(fd, filename, data, mode, **kwargs)
                raise KeyboardInterrupt()
            return original(fd, filename, data, mode, **kwargs)
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


class DNSInstallReloadTests(unittest.TestCase):
    """General RNDC reload after complete installation; RNDC is always mocked."""

    setUp = DNSInstallTests.setUp
    zone = DNSInstallTests.zone
    publish = DNSInstallTests.publish
    result = DNSInstallTests.result
    assert_empty_install = DNSInstallTests.assert_empty_install

    SECRET = "c2VjcmV0LWtleS1tYXRlcmlhbA=="

    def configure_reload(self):
        self.calls_log = self.root / "rndc-calls"
        self.exit_file = self.root / "rndc-exit"
        self.exit_file.write_text("0")
        self.rndc = self.root / "rndc"
        count = self.root / "rndc-count"
        self.rndc.write_text(
            "#!/bin/sh\n"
            + f"printf '%s\\n' \"$@\" >> '{self.calls_log}'\n"
            + f"echo call >> '{count}'\n"
            + "printf 'rndc: \\033[31mreload output\\007\\n'\n"
            + f"exit $(cat '{self.exit_file}')\n")
        self.rndc.chmod(0o700)
        self.key = self.root / "rndc.key"
        self.key.write_text('key "rndc-key" { algorithm hmac-sha256; secret "%s"; };\n' % self.SECRET)
        self.key.chmod(0o600)
        self.base_config = self.config_path.read_text()
        self.config_path.write_text(self.base_config + f"rndc = {self.rndc}\nrndc_key = {self.key}\n")
        self.config = installer.load_config(self.config_path)

    def invoke(self, dry_run=False):
        stderr = StringIO()
        with patch("sys.stderr", stderr), patch.object(installer, "__file__", str(self.script)):
            code = installer.main(["--config", str(self.config_path)] + (["--dry-run"] if dry_run else []))
        self.stderr = stderr.getvalue()
        self.assertNotIn(self.SECRET, self.stderr)
        return code

    def rndc_calls(self):
        path = self.root / "rndc-count"
        return len(path.read_text().splitlines()) if path.exists() else 0

    def pending_path(self):
        return self.paths["state"] / installer.RELOAD_NAME

    def assert_receipts_safe(self):
        for path in self.paths["outbox"].iterdir():
            self.assertNotIn(self.SECRET, path.read_text())
            self.assertNotIn(str(self.key), path.read_text())

    def test_reload_configuration_parsing_and_validation(self):
        self.configure_reload()
        self.assertEqual(self.config["rndc"], self.rndc)
        self.assertEqual(self.config["rndc_key"], self.key)
        self.assertEqual(self.config["named_checkzone"], self.validator)
        self.config_path.write_text(self.base_config)
        self.assertNotIn("rndc", installer.load_config(self.config_path))
        for text, message in (
            (self.base_config + f"rndc = {self.rndc}\n", "configured together"),
            (self.base_config + f"rndc_key = {self.key}\n", "configured together"),
            (self.base_config + f"rndc = bin/rndc\nrndc_key = {self.key}\n", "absolute"),
            (self.base_config + f"rndc = {self.rndc}\nrndc_key = {self.root}/../rndc.key\n", "absolute"),
            (self.base_config + f"rndc = {self.rndc}\nrndc_key = {self.paths['state']}/rndc.key\n", "outside"),
            (self.base_config + f"rndc = {self.paths['inbox']}/rndc\nrndc_key = {self.key}\n", "outside"),
            (self.base_config + f"rndc = {self.rndc}\nrndc_key = {self.rndc}\n", "distinct"),
            (self.base_config + f"utils_bin = {self.root}\n", "Invalid configuration"),
            (self.base_config + f"utils_bin = {self.root}\nrndc = {self.rndc}\nrndc_key = {self.key}\n",
             "Invalid configuration"),
            (self.base_config.replace(f"named_checkzone = {self.validator}\n", "")
             + f"rndc = {self.rndc}\nrndc_key = {self.key}\n", "Invalid configuration"),
        ):
            with self.subTest(text=text):
                self.config_path.write_text(text)
                with self.assertRaises(installer.InstallError) as raised:
                    installer.load_config(self.config_path)
                self.assertEqual(raised.exception.code, 2)
                self.assertIn(message, str(raised.exception))

    def test_example_configuration_uses_verified_separate_paths(self):
        text = (Path(installer.__file__).parent / "dns_install.ini.example").read_text()
        self.assertIn("named_checkzone = /volume1/@appstore/DNSServer/bin/named-checkzone\n", text)
        self.assertIn("rndc = /volume1/@appstore/DNSServer/bin/rndc\n", text)
        self.assertIn("rndc_key = /volume1/@appstore/DNSServer/named/rndc.key\n", text)
        self.assertNotIn("utils_bin", text)
        self.assertNotIn("saver.intranet", text)

    def test_exact_general_reload_argv_once_after_complete_installation(self):
        self.configure_reload()
        self.publish(suffix="b")
        original = subprocess.run
        calls = []
        def checked(args, **kwargs):
            calls.append((list(args), kwargs))
            if args[0] == str(self.rndc):
                self.assertFalse((self.paths["state"] / installer.JOURNAL_NAME).exists())
                for name in self.names:
                    self.assertEqual((self.paths["destination"] / name).read_bytes(), self.zone(self.serial))
            return original(args, **kwargs)
        with patch.object(installer.subprocess, "run", side_effect=checked):
            self.assertEqual(self.invoke(), 0)
        reloads = [(args, kwargs) for args, kwargs in calls if args[0] == str(self.rndc)]
        self.assertEqual(len(reloads), 1)
        args, kwargs = reloads[0]
        self.assertEqual(args, [str(self.rndc), "-k", str(self.key), "-s", "127.0.0.1",
                                "-p", "953", "reload"])
        self.assertEqual(installer.reload_command(self.config), args)
        self.assertFalse(kwargs["shell"])
        self.assertEqual(kwargs["timeout"], installer.RELOAD_TIMEOUT)
        self.assertEqual(kwargs["stdin"], subprocess.DEVNULL)
        self.assertFalse(any(name in args for name in self.names))
        self.assertFalse(any("systemctl" in str(a) or "restart" in str(a)
                             for call_args, _ in calls for a in call_args))
        self.assertEqual(self.calls_log.read_text().splitlines(),
                         ["-k", str(self.key), "-s", "127.0.0.1", "-p", "953", "reload"])
        self.assertEqual(calls[-1][0][0], str(self.rndc))

    def test_successful_reload_receipts_and_pending_cleared(self):
        self.configure_reload()
        second = self.publish(suffix="b")
        self.assertEqual(self.invoke(), 0)
        self.assertEqual(self.rndc_calls(), 1)
        first = self.result()
        self.assertEqual((first["status"], first["reload"]), ("installed", "succeeded"))
        self.assertIn("Serving of the new records not verified", first["summary"])
        other = self.result(second.name)
        self.assertEqual((other["status"], other["reload"]), ("already_installed", "succeeded"))
        self.assertFalse(self.pending_path().exists())
        self.assertIn("General RNDC reload succeeded", self.stderr)
        self.assert_receipts_safe()
        self.assertEqual(self.invoke(), 0)
        self.assertEqual(self.rndc_calls(), 1)

    def test_nonzero_exit_then_retry_without_resend_or_reinstall(self):
        self.configure_reload()
        self.exit_file.write_text("1")
        self.assertEqual(self.invoke(), 8)
        receipt = self.result()
        self.assertEqual((receipt["status"], receipt["reload"]), ("installed", "failed"))
        self.assertIn("exit status 1", self.stderr)
        self.assertIn("reload output", self.stderr)
        self.assertNotIn("\x1b", self.stderr)
        self.assert_receipts_safe()
        for name in self.names:
            self.assertEqual((self.paths["destination"] / name).read_bytes(), self.zone(self.serial))
        state = (self.paths["state"] / installer.STATE_NAME).read_bytes()
        self.assertTrue(self.pending_path().exists())
        self.assertFalse((self.paths["state"] / installer.JOURNAL_NAME).exists())
        # Still failing: retried every run, receipt stays failed, nothing reinstalled.
        with patch.object(installer, "snapshot") as snapshot, \
                patch.object(installer, "install") as install:
            self.assertEqual(self.invoke(), 8)
            snapshot.assert_not_called()
            install.assert_not_called()
        self.assertEqual(self.rndc_calls(), 2)
        # The delivery may even disappear from the inbox: the durable record drives the retry.
        source = self.paths["inbox"] / self.delivery
        source.rename(self.root / "removed-delivery")
        self.exit_file.write_text("0")
        with patch.object(installer, "snapshot") as snapshot, \
                patch.object(installer, "install") as install:
            self.assertEqual(self.invoke(), 0)
            snapshot.assert_not_called()
            install.assert_not_called()
        self.assertEqual(self.rndc_calls(), 3)
        receipt = self.result()
        self.assertEqual((receipt["status"], receipt["reload"]), ("installed", "succeeded"))
        self.assertFalse(self.pending_path().exists())
        self.assertEqual((self.paths["state"] / installer.STATE_NAME).read_bytes(), state)

    def test_timeout_and_startup_errors_are_reload_failures(self):
        self.configure_reload()
        original = subprocess.run
        for error in (subprocess.TimeoutExpired("rndc", installer.RELOAD_TIMEOUT),
                      PermissionError("cannot execute"), FileNotFoundError("vanished")):
            with self.subTest(error=type(error).__name__):
                def fail(args, **kwargs):
                    if args[0] == str(self.rndc):
                        raise error
                    return original(args, **kwargs)
                with patch.object(installer.subprocess, "run", side_effect=fail):
                    self.assertEqual(self.invoke(), 8)
                self.assertEqual(self.result()["reload"], "failed")
                self.assertTrue(self.pending_path().exists())
                self.assertIn("timed out" if isinstance(error, subprocess.TimeoutExpired)
                              else "could not be started", self.stderr)
        self.assertEqual(self.invoke(), 0)
        self.assertEqual(self.result()["reload"], "succeeded")

    def test_missing_or_unsafe_key_or_binary_installs_nothing(self):
        self.configure_reload()
        cases = []
        def key_mode(mode):
            def apply():
                self.key.chmod(mode)
            return apply
        cases.extend(("key mode %o" % mode, key_mode(mode)) for mode in (0o644, 0o604, 0o620, 0o666))
        cases.append(("key missing", lambda: self.key.rename(self.root / "moved.key")))
        def key_symlink():
            self.key.rename(self.root / "real.key")
            self.key.symlink_to(self.root / "real.key")
        cases.append(("key symlink", key_symlink))
        def key_hardlink():
            os.link(self.key, self.root / "linked.key")
        cases.append(("key hardlink", key_hardlink))
        cases.append(("key directory", lambda: (self.key.unlink(), self.key.mkdir(mode=0o700))))
        cases.append(("rndc missing", lambda: self.rndc.unlink()))
        cases.append(("rndc writable", lambda: self.rndc.chmod(0o722)))
        cases.append(("rndc not executable", lambda: self.rndc.chmod(0o600)))
        for label, mutate in cases:
            with self.subTest(case=label):
                self.setUp()
                self.configure_reload()
                mutate()
                self.assertEqual(self.invoke(), 2)
                self.assert_empty_install()
                self.assertEqual(list(self.paths["outbox"].iterdir()), [])
                self.assertEqual(self.rndc_calls(), 0)
                self.assertFalse(self.pending_path().exists())

    def test_dry_run_never_reloads(self):
        self.configure_reload()
        self.assertEqual(self.invoke(True), 0)
        self.assertEqual(self.rndc_calls(), 0)
        self.assert_empty_install()
        self.assertFalse(self.pending_path().exists())
        self.assertEqual(list(self.paths["outbox"].iterdir()), [])
        self.exit_file.write_text("1")
        self.assertEqual(self.invoke(), 8)
        pending = self.pending_path().read_bytes()
        self.assertEqual(self.invoke(True), 0)
        self.assertIn("dry run does not reload", self.stderr)
        self.assertEqual(self.rndc_calls(), 1)
        self.assertEqual(self.pending_path().read_bytes(), pending)

    def test_failed_or_incomplete_installation_never_reloads(self):
        self.configure_reload()
        self.validator.write_text("#!/bin/sh\nexit 1\n")
        self.assertEqual(self.invoke(), 5)
        self.assertEqual(self.rndc_calls(), 0)
        self.assertNotIn("reload", self.result())
        self.validator.write_text("#!/bin/sh\nexit 0\n")
        original = installer.atomic_write
        def fail(fd, filename, data, mode=0o600, **kwargs):
            if filename == installer.STATE_NAME:
                raise OSError("install failed")
            return original(fd, filename, data, mode, **kwargs)
        with patch.object(installer, "atomic_write", side_effect=fail):
            self.assertEqual(self.invoke(), 6)
        self.assertEqual(self.rndc_calls(), 0)
        self.assertEqual(self.result()["status"], "failed")
        self.assertNotIn("reload", self.result())
        self.assert_empty_install()
        self.assertFalse(self.pending_path().exists())

    def test_incomplete_rollback_defers_pending_reload(self):
        self.configure_reload()
        self.exit_file.write_text("1")
        self.assertEqual(self.invoke(), 8)
        self.exit_file.write_text("0")
        self.publish(self.serial + 1, "b")
        original = installer.atomic_write
        fail_recovery = False
        def fail(fd, filename, data, mode=0o600, **kwargs):
            nonlocal fail_recovery
            if filename == installer.STATE_NAME:
                fail_recovery = True
                raise OSError("install failed")
            if fail_recovery and filename in self.names:
                raise OSError("rollback failed")
            return original(fd, filename, data, mode, **kwargs)
        with patch.object(installer, "atomic_write", side_effect=fail):
            self.assertEqual(self.invoke(), 7)
        self.assertEqual(self.rndc_calls(), 1)
        self.assertTrue((self.paths["state"] / installer.JOURNAL_NAME).exists())
        self.assertTrue(self.pending_path().exists())
        # Recovery first restores the complete previous set; the failed newer
        # delivery is retried, then ONE general reload covers the complete set.
        self.assertEqual(self.invoke(), 0)
        self.assertEqual(self.rndc_calls(), 2)
        self.assertFalse((self.paths["state"] / installer.JOURNAL_NAME).exists())
        self.assertEqual(self.result()["reload"], "superseded")
        self.assertEqual(self.result(f"dnsgrid-{self.serial + 1}-" + "b" * 32)["reload"], "succeeded")

    def test_superseded_and_already_installed_do_not_bypass_pending_reload(self):
        self.configure_reload()
        self.exit_file.write_text("1")
        self.assertEqual(self.invoke(), 8)
        same = self.publish(suffix="c")
        self.assertEqual(self.invoke(), 8)
        self.assertEqual((self.result(same.name)["status"], self.result(same.name)["reload"]),
                         ("already_installed", "failed"))
        newer = self.publish(self.serial + 1, "b")
        self.exit_file.write_text("0")
        before = self.rndc_calls()
        self.assertEqual(self.invoke(), 0)
        self.assertEqual(self.rndc_calls(), before + 1)
        self.assertEqual(self.result()["reload"], "superseded")
        self.assertEqual(self.result(same.name)["reload"], "superseded")
        self.assertEqual((self.result(newer.name)["status"], self.result(newer.name)["reload"]),
                         ("installed", "succeeded"))
        for name in self.names:
            self.assertEqual((self.paths["destination"] / name).read_bytes(), self.zone(self.serial + 1))
        self.assertFalse(self.pending_path().exists())

    def test_crash_after_install_before_pending_record_reloads_on_next_run(self):
        self.configure_reload()
        with patch.object(installer, "write_pending", side_effect=KeyboardInterrupt()):
            with self.assertRaises(KeyboardInterrupt):
                self.invoke()
        self.assertEqual(self.rndc_calls(), 0)
        self.assertEqual(list(self.paths["outbox"].iterdir()), [])
        self.assertTrue((self.paths["state"] / installer.STATE_NAME).exists())
        self.assertEqual(self.invoke(), 0)
        self.assertEqual(self.rndc_calls(), 1)
        self.assertEqual((self.result()["status"], self.result()["reload"]), ("already_installed", "succeeded"))

    def test_crash_after_reload_before_receipts_repeats_idempotent_reload(self):
        self.configure_reload()
        with patch.object(installer, "result", side_effect=KeyboardInterrupt()):
            with self.assertRaises(KeyboardInterrupt):
                self.invoke()
        self.assertEqual(self.rndc_calls(), 1)
        self.assertTrue(self.pending_path().exists())
        self.assertEqual(list(self.paths["outbox"].iterdir()), [])
        with patch.object(installer, "snapshot") as snapshot:
            self.assertEqual(self.invoke(), 0)
            snapshot.assert_not_called()
        self.assertEqual(self.rndc_calls(), 2)
        self.assertEqual((self.result()["status"], self.result()["reload"]), ("installed", "succeeded"))
        self.assertFalse(self.pending_path().exists())
        original = installer.write_pending
        def crash_on_clear(state, entries):
            if not entries:
                raise KeyboardInterrupt()
            return original(state, entries)
        self.publish(self.serial + 1, "b")
        with patch.object(installer, "write_pending", side_effect=crash_on_clear):
            with self.assertRaises(KeyboardInterrupt):
                self.invoke()
        self.assertTrue(self.pending_path().exists())
        self.assertEqual(self.invoke(), 0)
        self.assertEqual(self.rndc_calls(), 4)
        self.assertFalse(self.pending_path().exists())

    def test_invalid_pending_reload_state_blocks_installation(self):
        self.configure_reload()
        for content in ("{}", "not json", json.dumps({"version": 1, "deliveries": [
                {"delivery": "dnsgrid-1-" + "a" * 32, "serial": 2, "status": "installed",
                 "fingerprint": "0" * 64}]})):
            with self.subTest(content=content):
                self.pending_path().write_text(content)
                self.pending_path().chmod(0o600)
                self.assertEqual(self.invoke(), 7)
                self.assert_empty_install()
                self.assertEqual(self.rndc_calls(), 0)

    def test_receipt_schema_accepts_reload_field_and_legacy_receipts(self):
        self.configure_reload()
        self.assertEqual(self.invoke(), 0)
        path = self.paths["outbox"] / (self.delivery + ".json")
        receipt = json.loads(path.read_text())
        self.assertEqual(set(receipt), {"delivery", "serial", "status", "timestamp", "summary", "reload"})
        outbox = os.open(self.paths["outbox"], os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, outbox)
        self.assertTrue(installer.completed_result(outbox, self.delivery, self.serial))
        legacy = {key: value for key, value in receipt.items() if key != "reload"}
        path.write_text(json.dumps(legacy))
        self.assertTrue(installer.completed_result(outbox, self.delivery, self.serial))
        for bad in ({**receipt, "reload": "maybe"}, {**receipt, "status": "failed"}):
            path.write_text(json.dumps(bad))
            with self.assertRaises(installer.InstallError):
                installer.completed_result(outbox, self.delivery, self.serial)

    def test_legacy_configuration_installs_without_reload_and_says_so(self):
        self.assertEqual(self.invoke(), 0)
        receipt = self.result()
        self.assertEqual(set(receipt), {"delivery", "serial", "status", "timestamp", "summary"})
        self.assertEqual(receipt["status"], "installed")
        self.assertIn("RNDC reload not configured", receipt["summary"])
        self.assertIn("not confirmed loaded", self.stderr)
        self.assertFalse(self.pending_path().exists())

    def test_copied_script_reloads_with_stdlib_only(self):
        self.configure_reload()
        copied = self.root / "dns_install.py"
        copied.write_bytes(Path(installer.__file__).read_bytes())
        copied.chmod(0o700)
        process = subprocess.run([sys.executable, "-I", "-S", str(copied), "--config", str(self.config_path)],
                                 cwd=self.root, capture_output=True, text=True, timeout=15)
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertNotIn(self.SECRET, process.stdout + process.stderr)
        self.assertEqual(self.result()["reload"], "succeeded")
        self.assertEqual(self.rndc_calls(), 1)


if __name__ == "__main__":
    unittest.main()
