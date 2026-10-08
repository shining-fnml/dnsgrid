import copy
from datetime import datetime, timezone
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

from synology import dns_pull


class DNSPullTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix=".dns-pull-test-", dir=Path.cwd())
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.destination = self.root / "master"
        self.backups = self.root / "backups"
        self.destination.mkdir(mode=0o700)
        self.backups.mkdir(mode=0o700)
        self.key = self.root / "key"
        self.hosts = self.root / "known_hosts"
        self.validator = self.root / "named-checkzone"
        for path in (self.key, self.hosts, self.validator):
            path.write_text("fixture\n")
            path.chmod(0o600)
        self.validator.chmod(0o700)
        self.config_path = self.root / "dns-pull.ini"
        self.config_text = (
            "[dns_pull]\nsource_host = hub.example.net\nsource_user = dnsreader\n"
            "source_port = 2222\nsource_directory = /srv/dnsgrid/export\n"
            f"identity_file = {self.key}\nknown_hosts = {self.hosts}\n"
            f"destination_directory = {self.destination}\n"
            f"backup_directory = {self.backups}\nnamed_checkzone = {self.validator}\n"
        )
        self.config_path.write_text(self.config_text)
        self.config_path.chmod(0o600)
        self.config = dns_pull.load_config(self.config_path)
        self.serial = 2026100801
        self.generation = "dnsgrid-" + str(self.serial)
        self.zones = {
            "example.net": self.zone("example.net", self.serial),
            "17.24.10.in-addr.arpa": self.zone("17.24.10.in-addr.arpa", self.serial),
        }
        self.manifest = self.make_manifest()
        self.transfers = []
        self.checked = []

    def zone(self, name, serial, extra=""):
        return (
            f"$ORIGIN {name}.\n$TTL 3600\n"
            f"@ IN SOA ns.example.net. hostmaster.example.net. (\n"
            f" {serial} ; serial\n 3600 600 86400 60 )\n"
            f"@ IN NS ns.example.net.\n{extra}"
        ).encode("ascii")

    def make_manifest(self):
        return {
            "version": 1, "generation": self.generation, "serial": self.serial,
            "published_at": datetime(2026, 10, 8, 13, 0, tzinfo=timezone.utc).isoformat(),
            "zones": [
                {"name": name, "filename": name, "size": len(data), "sha256": dns_pull._digest(data)}
                for name, data in self.zones.items()
            ],
        }

    def fake_fetch(self, config, generation, filename, destination, limit):
        self.assertEqual(generation, self.generation)
        self.transfers.append(filename)
        data = json.dumps(self.manifest).encode("utf-8") if filename == "manifest.json" else self.zones[filename]
        destination.write_bytes(data)

    def fake_check(self, config, name, path, stage):
        self.checked.append(name)
        content = path.read_bytes().decode("ascii")
        return int(content.split("; serial")[0].split()[-1])

    def invoke(self, *extra, fetch=None, check=None):
        output, errors = StringIO(), StringIO()
        with (
            patch.object(dns_pull, "fetch", side_effect=fetch or self.fake_fetch),
            patch.object(dns_pull, "check_zone", side_effect=check or self.fake_check),
            patch("sys.stdout", output), patch("sys.stderr", errors),
        ):
            result = dns_pull.main([
                "--config", str(self.config_path), *extra,
                *([] if "--forced-command" in extra else [self.generation, str(self.serial)]),
            ])
        return result, output.getvalue(), errors.getvalue()

    def write_existing(self, serial=2026100800, mode=0o640):
        for name in self.zones:
            path = self.destination / name
            path.write_bytes(self.zone(name, serial))
            path.chmod(mode)
            os.utime(path, ns=(1_700_000_000_000_000_000, 1_700_000_000_000_000_001))

    def state_path(self):
        return self.backups / dns_pull.STATE_NAME

    def write_state(self, manifest):
        self.state_path().write_text(json.dumps(manifest))
        self.state_path().chmod(0o600)

    def assert_not_installed(self):
        self.assertEqual(list(self.destination.iterdir()), [])
        self.assertFalse(self.state_path().exists())
        self.assertEqual(list(self.backups.glob("backup-*")), [])

    def test_standalone_copied_help_without_repository_or_site_packages(self):
        script = self.root / "copied-dns-pull.py"
        script.write_bytes(Path(dns_pull.__file__).read_bytes())
        result = subprocess.run(
            [sys.executable, "-I", "-S", str(script), "--help"],
            cwd=self.root, capture_output=True, text=True, timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        for value in ("--dry-run", "--forced-command", "--config", "Exit codes:"):
            self.assertIn(value, result.stdout)

    def test_request_validation_date_counter_uint32_and_injection(self):
        for serial in ("2026100800", "2026100899", "2024022900"):
            self.assertEqual(dns_pull.validate_request("dnsgrid-" + serial, serial)[1], int(serial))
        for serial in ("202610080", "02026100800", "2026022900", "2026130100",
                       "2026103200", "4295010100", "+2026100801", "2026100801\n",
                       "２０２６１００８０１", "2026100801;id", None):
            with self.subTest(serial=serial), self.assertRaises(dns_pull.PullError):
                dns_pull.validate_request("dnsgrid-" + str(serial), serial)
        for generation in ("../dnsgrid-2026100801", "dnsgrid-2026100800",
                           "dnsgrid-20261008n01", "-2026100801", None):
            with self.subTest(generation=generation), self.assertRaises(dns_pull.PullError):
                dns_pull.validate_request(generation, str(self.serial))

    def test_forced_command_exact_protocol(self):
        with patch.dict(os.environ, {"SSH_ORIGINAL_COMMAND": f"dnsgrid-update {self.generation} {self.serial}"}):
            result, output, _ = self.invoke("--forced-command", "--dry-run")
        self.assertEqual(result, 0)
        self.assertIn("Dry run", output)
        self.assert_not_installed()

    def test_forced_command_rejects_extra_arguments_quoting_and_whitespace(self):
        base = f"dnsgrid-update {self.generation} {self.serial}"
        for command in ("", base + "\n", base + ";id", base + " extra",
                        " " + base, base.replace(" ", "  ", 1),
                        base.replace(self.generation, "'" + self.generation + "'"),
                        base.replace("dnsgrid-update", "update")):
            with self.subTest(command=command), patch.dict(os.environ, {"SSH_ORIGINAL_COMMAND": command}):
                result, _, errors = self.invoke("--forced-command")
                self.assertEqual(result, 2)
                self.assertIn("Rejected", errors)
        self.assertEqual(self.transfers, [])

    def test_forced_mode_rejects_positional_arguments(self):
        with patch("sys.stderr", StringIO()), patch.object(dns_pull, "load_config") as load:
            result = dns_pull.main(["--forced-command", self.generation, str(self.serial)])
        self.assertEqual(result, 2)
        load.assert_not_called()

    def test_manifest_valid_utc_suffixes_and_microseconds(self):
        for timestamp in ("2026-10-08T13:00:00Z", "2026-10-08T13:00:00+00:00",
                          "2026-10-08T13:00:00.123456Z", "2026-10-08T13:00:00.123456+00:00"):
            self.manifest["published_at"] = timestamp
            with self.subTest(timestamp=timestamp):
                self.assertEqual(self.invoke("--dry-run")[0], 0)

    def test_reserved_manifest_filename_rejected_before_zone_fetch(self):
        self.manifest["zones"][0]["name"] = "manifest.json"
        self.manifest["zones"][0]["filename"] = "manifest.json"
        result, _, errors = self.invoke()
        self.assertEqual(result, 5)
        self.assertIn("Invalid generation manifest", errors)
        self.assertEqual(self.transfers, ["manifest.json"])
        self.assert_not_installed()

    def test_manifest_schema_types_names_times_and_limits_fail_closed(self):
        changes = [
            ("version", True), ("version", 2), ("serial", str(self.serial)), ("serial", True),
            ("generation", "dnsgrid-2026100800"), ("published_at", "2026-10-08T13:00:00"),
            ("published_at", "2026-10-08T13:00:00+01:00"), ("published_at", "2026-02-30T13:00:00Z"),
            ("zones", []), ("zones", {}), ("zones", [self.manifest["zones"][0]] * 257),
            ("extra", "value"),
        ]
        for field, value in changes:
            manifest = {**self.manifest, field: value}
            with self.subTest(field=field, value=str(value)[:60]), self.assertRaises(dns_pull.PullError):
                dns_pull.decode_manifest(json.dumps(manifest).encode(), self.generation, self.serial)
        for name in ("../example.net", "example.net/evil", "-x.net", "x-.net", "Example.net",
                     "x", "x..net", "x.net.", "*.net", "x_net.net", "é.net", "a" * 64 + ".net",
                     "x.net\n", ".net", "manifest.json"):
            manifest = copy.deepcopy(self.manifest)
            manifest["zones"][0]["name"] = manifest["zones"][0]["filename"] = name
            with self.subTest(name=name), self.assertRaises(dns_pull.PullError):
                dns_pull.decode_manifest(json.dumps(manifest).encode(), self.generation, self.serial)
        for field, value in (("filename", "../zone"), ("size", True), ("size", 0),
                             ("size", dns_pull.MAX_ZONE + 1), ("sha256", "A" * 64),
                             ("sha256", "0" * 63), ("extra", "value")):
            manifest = copy.deepcopy(self.manifest)
            manifest["zones"][0][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(dns_pull.PullError):
                dns_pull.decode_manifest(json.dumps(manifest).encode(), self.generation, self.serial)
        duplicate = copy.deepcopy(self.manifest)
        duplicate["zones"].append(duplicate["zones"][0])
        with self.assertRaises(dns_pull.PullError):
            dns_pull.decode_manifest(json.dumps(duplicate).encode(), self.generation, self.serial)
        data = json.dumps(self.manifest).replace('"version": 1', '"version": 1, "version": 1').encode()
        for data in (data, b"\xff", b"[]", b" " * (dns_pull.MAX_MANIFEST + 1)):
            with self.subTest(data=data[:30]), self.assertRaises(dns_pull.PullError):
                dns_pull.decode_manifest(data, self.generation, self.serial)

    def test_configuration_rejects_unprotected_files_symlinks_and_injection(self):
        self.config_path.chmod(0o622)
        with self.assertRaises(dns_pull.PullError):
            dns_pull.load_config(self.config_path)
        self.config_path.chmod(0o600)
        alias = self.root / "linked.ini"
        alias.symlink_to(self.config_path)
        with self.assertRaises(dns_pull.PullError):
            dns_pull.load_config(alias)
        original = dns_pull.os.geteuid()
        with patch.object(dns_pull.os, "geteuid", return_value=original + 1):
            if self.config_path.stat().st_uid != 0:
                with self.assertRaises(dns_pull.PullError):
                    dns_pull.load_config(self.config_path)
        for old, new in (
            ("hub.example.net", "-oProxyCommand=evil"), ("hub.example.net", "hub:22"),
            ("dnsreader", "user;id"), ("2222", "0"), ("2222", "65536"),
            ("/srv/dnsgrid/export", "/srv/../etc"), ("/srv/dnsgrid/export", "/srv/zone files"),
            ("/srv/dnsgrid/export", "/srv//zones"), ("[dns_pull]", "[DEFAULT]"),
        ):
            self.config_path.write_text(self.config_text.replace(old, new))
            with self.subTest(new=new), self.assertRaises(dns_pull.PullError):
                dns_pull.load_config(self.config_path)
        for addition in ("command = evil\n", "timeout = 99999\n", "[other]\nx = y\n"):
            self.config_path.write_text(self.config_text + addition)
            with self.assertRaises(dns_pull.PullError):
                dns_pull.load_config(self.config_path)

    def test_configuration_defaults_and_ipv6_host(self):
        text = self.config_text.replace(f"destination_directory = {self.destination}\n", "")
        self.config_path.write_text(text.replace("hub.example.net", "2001:db8::1"))
        config = dns_pull.load_config(self.config_path)
        self.assertEqual(config["destination_directory"], Path(dns_pull.DEFAULT_DESTINATION))
        self.assertEqual(config["source_host"], "[2001:db8::1]")

    def test_source_host_rejects_ipv6_scope_and_controls(self):
        for host in ("fe80::1%eth0", "fe80::1%;evil", "fe80::1%../../evil",
                     "fe80::1%\x01evil", "fe80::1%\x7fevil", "hub\x01.example.net"):
            self.config_path.write_text(self.config_text.replace("hub.example.net", host))
            with self.subTest(host=host), self.assertRaises(dns_pull.PullError):
                dns_pull.load_config(self.config_path)

    def test_symlink_directory_credential_and_destination_rejected(self):
        alias = self.root / "alias"
        alias.symlink_to(self.destination, target_is_directory=True)
        for text in (
            self.config_text.replace(str(self.destination), str(alias)),
            self.config_text.replace(str(self.key), str(alias / "key")),
        ):
            self.config_path.write_text(text)
            with self.assertRaises(dns_pull.PullError):
                config = dns_pull.load_config(self.config_path)
                dns_pull.pull(config, self.generation, self.serial)
        self.destination.chmod(0o777)
        with self.assertRaises(dns_pull.PullError):
            dns_pull.pull(self.config, self.generation, self.serial)

    def test_scp_arguments_modern_sftp_strict_keys_no_shell_bounded_output(self):
        with patch.object(dns_pull.subprocess, "run") as run:
            dns_pull.fetch(self.config, self.generation, "manifest.json", self.root / "download", dns_pull.MAX_MANIFEST)
        args = run.call_args.args[0]
        kwargs = run.call_args.kwargs
        self.assertNotIn("-O", args)
        self.assertIn("BatchMode=yes", args)
        self.assertIn("StrictHostKeyChecking=yes", args)
        self.assertIn("IdentitiesOnly=yes", args)
        self.assertIn("ForwardAgent=no", args)
        self.assertIn("ClearAllForwardings=yes", args)
        self.assertIn("IdentityAgent=none", args)
        self.assertIn("UserKnownHostsFile=" + str(self.hosts), args)
        self.assertEqual(args[args.index("-F") + 1], "/dev/null")
        self.assertEqual(args[args.index("-P") + 1], "2222")
        self.assertEqual(args[-2], f"dnsreader@hub.example.net:/srv/dnsgrid/export/generations/{self.generation}/manifest.json")
        self.assertFalse(kwargs["shell"])
        self.assertEqual(kwargs["timeout"], dns_pull.TIMEOUT)
        self.assertEqual(kwargs["stdout"], subprocess.DEVNULL)
        self.assertEqual(kwargs["stderr"], subprocess.DEVNULL)
        self.assertTrue(callable(kwargs["preexec_fn"]))

    def test_fetch_errors_and_timeout_do_not_echo_remote_output(self):
        for error in (
            subprocess.CalledProcessError(1, ["scp"], output="secret", stderr="\x1b[31mevil"),
            subprocess.TimeoutExpired(["scp"], 120, output="secret"),
            FileNotFoundError("sensitive path"),
        ):
            with self.subTest(error=type(error).__name__), patch.object(dns_pull.subprocess, "run", side_effect=error):
                with self.assertRaises(dns_pull.PullError) as raised:
                    dns_pull.fetch(self.config, self.generation, "manifest.json", self.root / "download", dns_pull.MAX_MANIFEST)
            self.assertEqual(raised.exception.code, 4)
            self.assertNotIn("secret", str(raised.exception))
            self.assertNotIn("sensitive", str(raised.exception))

    def test_checkzone_serial_output_and_unsigned_legacy_serial(self):
        name = "example.net"
        for serial in (42, self.serial, 0xFFFFFFFF):
            def run(args, **kwargs):
                kwargs["stdout"].write(f"zone {name}/IN: loaded serial {serial}\nOK\n".encode())
                return subprocess.CompletedProcess(args, 0)
            with patch.object(dns_pull.subprocess, "run", side_effect=run) as command:
                self.assertEqual(dns_pull.check_zone(self.config, name, self.key, self.root), serial)
            self.assertEqual(command.call_args.args[0], [str(self.validator), name, str(self.key)])
            self.assertFalse(command.call_args.kwargs["shell"])

    def test_checkzone_unsupported_output_invalid_zone_and_missing_validator(self):
        name = "example.net"
        for output in (
            b"OK\n", b"zone evil.net/IN: loaded serial 2026100801\nOK\n",
            b"zone example.net/IN: loaded serial 4294967296\nOK\n",
            b"zone example.net/IN: loaded serial 2026100801\nFAILED\n",
            b"\xff", b"x" * (dns_pull.MAX_MANIFEST + 1),
        ):
            def run(args, **kwargs):
                kwargs["stdout"].write(output)
                return subprocess.CompletedProcess(args, 0)
            with self.subTest(output=output[:40]), patch.object(dns_pull.subprocess, "run", side_effect=run):
                with self.assertRaises(dns_pull.PullError):
                    dns_pull.check_zone(self.config, name, self.key, self.root)
        with patch.object(dns_pull.subprocess, "run", side_effect=subprocess.CalledProcessError(1, ["named-checkzone"])):
            with self.assertRaises(dns_pull.PullError) as raised:
                dns_pull.check_zone(self.config, name, self.key, self.root)
        self.assertEqual(raised.exception.code, 5)
        self.validator.unlink()
        with self.assertRaises(dns_pull.PullError) as raised:
            dns_pull.check_zone(self.config, name, self.key, self.root)
        self.assertEqual(raised.exception.code, 5)

    def test_child_disk_cpu_and_memory_limits(self):
        with (
            patch.object(dns_pull.resource, "getrlimit", return_value=(dns_pull.resource.RLIM_INFINITY,) * 2),
            patch.object(dns_pull.resource, "setrlimit") as limit,
        ):
            dns_pull._file_limit(1024)
        self.assertIn(unittest.mock.call(dns_pull.resource.RLIMIT_FSIZE, (1024, 1024)), limit.call_args_list)
        self.assertEqual(limit.call_count, 4)

    def test_install_every_zone_backup_metadata_state_and_unrelated_files(self):
        self.write_existing()
        unrelated = self.destination / "unrelated.zone"
        unrelated.write_bytes(b"do not touch\n")
        old = {name: ((self.destination / name).read_bytes(), (self.destination / name).stat())
               for name in self.zones}
        result, output, errors = self.invoke()
        self.assertEqual((result, errors), (0, ""))
        self.assertIn("Installed 2 zone file(s)", output)
        self.assertIn("not performed", output)
        self.assertEqual(self.transfers, ["manifest.json", *self.zones])
        self.assertEqual(self.checked, [*self.zones, *self.zones])
        for name, data in self.zones.items():
            path = self.destination / name
            self.assertEqual(path.read_bytes(), data)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o640)
            self.assertEqual((path.stat().st_uid, path.stat().st_gid), (old[name][1].st_uid, old[name][1].st_gid))
        backups = list(self.backups.glob("backup-*"))
        self.assertEqual(len(backups), 1)
        self.assertEqual(stat.S_IMODE(backups[0].stat().st_mode), 0o700)
        metadata = json.loads((backups[0] / ".metadata.json").read_text())
        for name in self.zones:
            self.assertEqual((backups[0] / name).read_bytes(), old[name][0])
            self.assertEqual(metadata["zones"][name]["mode"], 0o640)
            self.assertEqual(metadata["zones"][name]["mtime_ns"], old[name][1].st_mtime_ns)
        self.assertEqual(json.loads(self.state_path().read_text()), self.manifest)
        self.assertEqual(stat.S_IMODE(self.state_path().stat().st_mode), 0o600)
        self.assertEqual(unrelated.read_bytes(), b"do not touch\n")

    def test_new_targets_have_public_readable_modes_and_no_unrelated_removal(self):
        self.assertEqual(self.invoke()[0], 0)
        for name in self.zones:
            self.assertEqual(stat.S_IMODE((self.destination / name).stat().st_mode), 0o644)
        removed = list(self.zones)[1]
        self.serial += 1
        self.generation = "dnsgrid-" + str(self.serial)
        self.zones = {list(self.zones)[0]: self.zone(list(self.zones)[0], self.serial)}
        self.manifest = self.make_manifest()
        self.assertEqual(self.invoke()[0], 0)
        self.assertTrue((self.destination / removed).exists())

    def test_idempotent_retry_checks_actual_files_not_just_state(self):
        self.assertEqual(self.invoke()[0], 0)
        backups = list(self.backups.glob("backup-*"))
        self.checked.clear()
        result, output, _ = self.invoke()
        self.assertEqual(result, 0)
        self.assertIn("Already installed", output)
        self.assertEqual(list(self.backups.glob("backup-*")), backups)
        self.assertEqual(self.checked, [*self.zones, *self.zones])
        name = next(iter(self.zones))
        (self.destination / name).write_bytes(self.zone(name, self.serial, "tampered IN A 192.0.2.1\n"))
        result, _, errors = self.invoke()
        self.assertEqual(result, 5)
        self.assertIn("different installed", errors)
        self.assertEqual(list(self.backups.glob("backup-*")), backups)

    def test_missing_installed_file_is_not_claimed_idempotent(self):
        self.assertEqual(self.invoke()[0], 0)
        (self.destination / next(iter(self.zones))).unlink()
        result, output, _ = self.invoke()
        self.assertEqual(result, 0)
        self.assertIn("Installed", output)
        self.assertEqual(len(list(self.backups.glob("backup-*"))), 2)

    def test_lower_than_state_rejected_before_fetch(self):
        newer = copy.deepcopy(self.manifest)
        newer["serial"] += 1
        newer["generation"] = "dnsgrid-" + str(newer["serial"])
        self.write_state(newer)
        result, _, errors = self.invoke()
        self.assertEqual(result, 5)
        self.assertIn("downgrade", errors)
        self.assertEqual(self.transfers, [])
        self.assertEqual(list(self.destination.iterdir()), [])

    def test_equal_state_different_zone_set_rejected(self):
        state = copy.deepcopy(self.manifest)
        state["zones"] = state["zones"][:1]
        self.write_state(state)
        result, _, errors = self.invoke()
        self.assertEqual(result, 5)
        self.assertIn("different generation", errors)
        self.assertEqual(self.transfers, ["manifest.json"])

    def test_installed_serial_downgrade_and_equal_changed_bytes_rejected(self):
        for serial in (self.serial + 1, self.serial):
            self.write_existing(serial)
            if serial == self.serial:
                name = next(iter(self.zones))
                (self.destination / name).write_bytes(self.zone(name, serial, "other IN A 192.0.2.3\n"))
            before = {p.name: p.read_bytes() for p in self.destination.iterdir()}
            result, _, _ = self.invoke()
            self.assertEqual(result, 5)
            self.assertEqual({p.name: p.read_bytes() for p in self.destination.iterdir()}, before)
            self.assertFalse(self.state_path().exists())
            self.assertEqual(list(self.backups.glob("backup-*")), [])

    def test_numeric_legacy_serial_above_date_serial_is_not_lowered(self):
        self.write_existing(4_000_000_000)
        self.assertEqual(self.invoke()[0], 5)

    def test_zone_serial_mismatch_or_unsupported_validator_installs_nothing(self):
        for check in (
            lambda *args: self.serial - 1,
            lambda *args: (_ for _ in ()).throw(dns_pull.PullError("Unsupported serial output.", 5)),
        ):
            self.assertEqual(self.invoke(check=check)[0], 5)
            self.assert_not_installed()

    def test_every_zone_validated_before_any_master_modification(self):
        def check(config, name, path, stage):
            self.assertEqual(list(self.destination.iterdir()), [])
            if name == list(self.zones)[1]:
                raise dns_pull.PullError("Zone validation failed.", 5)
            return self.fake_check(config, name, path, stage)
        with patch.object(dns_pull, "backup_targets") as backup:
            self.assertEqual(self.invoke(check=check)[0], 5)
            backup.assert_not_called()
        self.assert_not_installed()

    def test_missing_real_validator_installs_nothing(self):
        self.validator.unlink()
        self.assertEqual(self.invoke(check=dns_pull.check_zone)[0], 5)
        self.assert_not_installed()

    def test_checksum_size_and_external_include_rejected(self):
        name = next(iter(self.zones))
        for content in (self.zones[name] + b"\n", b"x", self.zone(name, self.serial, "$INCLUDE /etc/named.conf\n")):
            self.zones[name] = content
            if b"INCLUDE" in content:
                self.manifest = self.make_manifest()
            result, _, _ = self.invoke()
            self.assertEqual(result, 5)
            self.assert_not_installed()

    def test_malicious_fetched_symlink_hardlink_fifo_and_oversized_manifest(self):
        innocent = self.root / "innocent"
        innocent.write_bytes(b"private")
        for kind in ("symlink", "hardlink", "fifo", "oversized"):
            def fetch(config, generation, filename, destination, limit):
                if kind == "symlink":
                    destination.symlink_to(innocent)
                elif kind == "hardlink":
                    os.link(innocent, destination)
                elif kind == "fifo":
                    os.mkfifo(destination)
                else:
                    destination.write_bytes(b" " * (dns_pull.MAX_MANIFEST + 1))
            with self.subTest(kind=kind):
                result, _, _ = self.invoke(fetch=fetch)
                self.assertNotEqual(result, 0)
                self.assert_not_installed()
                self.assertEqual(innocent.read_bytes(), b"private")

    def test_symlink_existing_target_state_and_lock_rejected(self):
        innocent = self.root / "innocent"
        innocent.write_bytes(b"private")
        for target in (self.destination / next(iter(self.zones)), self.state_path(), self.backups / dns_pull.LOCK_NAME):
            if target.exists():
                target.unlink()
            target.symlink_to(innocent)
            with self.subTest(target=target.name):
                self.assertNotEqual(self.invoke()[0], 0)
                self.assertEqual(innocent.read_bytes(), b"private")
            target.unlink()

    def test_malicious_zone_transfer_symlink_and_oversize_rejected(self):
        name = next(iter(self.zones))
        innocent = self.root / "innocent"
        innocent.write_bytes(self.zones[name])
        for kind in ("symlink", "oversized"):
            def fetch(config, generation, filename, destination, limit):
                if filename != name:
                    return self.fake_fetch(config, generation, filename, destination, limit)
                if kind == "symlink":
                    destination.symlink_to(innocent)
                else:
                    destination.write_bytes(b"x" * (dns_pull.MAX_ZONE + 1))
            with self.subTest(kind=kind):
                self.assertNotEqual(self.invoke(fetch=fetch)[0], 0)
                self.assert_not_installed()
                self.assertEqual(innocent.read_bytes(), self.zones[name])

    def test_corrupt_state_and_unprotected_state_fail_closed(self):
        for data in (b"invalid", b"{}", b"[]", b'{"generation":"dnsgrid-2026100801","serial":true}'):
            self.state_path().write_bytes(data)
            self.state_path().chmod(0o600)
            self.assertNotEqual(self.invoke()[0], 0)
        self.write_state(self.manifest)
        self.state_path().chmod(0o666)
        self.assertEqual(self.invoke()[0], 2)
        self.assertEqual(self.transfers, [])

    def test_disk_space_preflight_installs_nothing(self):
        class Disk:
            f_bavail = 0
            f_frsize = 4096
        with patch.object(dns_pull.os, "statvfs", return_value=Disk()):
            self.assertEqual(self.invoke()[0], 4)
        self.assert_not_installed()
        self.assertEqual(self.transfers, ["manifest.json"])

    def test_lock_contention_entire_fetch_is_locked(self):
        with dns_pull.run_lock(self.backups):
            result, _, errors = self.invoke()
        self.assertEqual(result, 3)
        self.assertIn("Another", errors)
        self.assertEqual(self.transfers, [])
        def fetch(*args):
            with self.assertRaises(dns_pull.PullError) as raised:
                with dns_pull.run_lock(self.backups):
                    self.fail("Lock was not held during fetch.")
            self.assertEqual(raised.exception.code, 3)
            self.fake_fetch(*args)
        self.assertEqual(self.invoke("--dry-run", fetch=fetch)[0], 0)

    def test_dry_run_leaves_installed_files_state_and_backups_unchanged(self):
        self.write_existing()
        before = {p.name: p.read_bytes() for p in self.destination.iterdir()}
        result, output, errors = self.invoke("--dry-run")
        self.assertEqual((result, errors), (0, ""))
        self.assertIn("Dry run", output)
        self.assertEqual({p.name: p.read_bytes() for p in self.destination.iterdir()}, before)
        self.assertFalse(self.state_path().exists())
        self.assertEqual(list(self.backups.glob("backup-*")), [])
        self.assertEqual(list(self.backups.glob(".dnsgrid-stage-*")), [])

    def test_backup_failure_installs_nothing(self):
        with patch.object(dns_pull, "_write_private", side_effect=OSError("disk full secret")):
            result, _, errors = self.invoke()
        self.assertEqual(result, 6)
        self.assertNotIn("secret", errors)
        self.assertEqual(list(self.destination.iterdir()), [])
        self.assertFalse(self.state_path().exists())

    def test_replace_failure_restores_all_old_bytes_and_metadata(self):
        self.write_existing()
        before = {name: ((self.destination / name).read_bytes(), (self.destination / name).stat())
                  for name in self.zones}
        original_replace = os.replace
        failed = False
        def replace(source, destination):
            nonlocal failed
            if Path(destination).name == list(self.zones)[1] and not failed:
                failed = True
                raise OSError("disk full")
            return original_replace(source, destination)
        with patch.object(dns_pull.os, "replace", side_effect=replace):
            result, _, errors = self.invoke()
        self.assertEqual(result, 6)
        self.assertIn("restored", errors)
        for name, (data, info) in before.items():
            path = self.destination / name
            restored = path.stat()
            self.assertEqual(restored.st_mtime_ns, info.st_mtime_ns)
            self.assertEqual(stat.S_IMODE(restored.st_mode), stat.S_IMODE(info.st_mode))
            self.assertEqual((restored.st_uid, restored.st_gid), (info.st_uid, info.st_gid))
            self.assertEqual(path.read_bytes(), data)
        self.assertFalse(self.state_path().exists())
        self.assertEqual(list(self.destination.glob(".dnsgrid-write-*")), [])
        self.assertEqual(len(list(self.backups.glob("backup-*"))), 1)

    def test_replace_failure_removes_only_new_targets(self):
        unrelated = self.destination / "unrelated.zone"
        unrelated.write_bytes(b"keep")
        original_replace = os.replace
        failed = False
        def replace(source, destination):
            nonlocal failed
            if Path(destination).name == list(self.zones)[1] and not failed:
                failed = True
                raise OSError("failure")
            return original_replace(source, destination)
        with patch.object(dns_pull.os, "replace", side_effect=replace):
            self.assertEqual(self.invoke()[0], 6)
        self.assertEqual(list(self.destination.iterdir()), [unrelated])
        self.assertEqual(unrelated.read_bytes(), b"keep")
        self.assertFalse(self.state_path().exists())

    def test_final_state_write_failure_rolls_back_zones_and_prior_state(self):
        self.assertEqual(self.invoke()[0], 0)
        old_state = self.state_path().read_bytes()
        old_targets = {name: (self.destination / name).read_bytes() for name in self.zones}
        self.serial += 1
        self.generation = "dnsgrid-" + str(self.serial)
        self.zones = {name: self.zone(name, self.serial) for name in self.zones}
        self.manifest = self.make_manifest()
        real_atomic = dns_pull.atomic_write
        failed = False
        def atomic(path, *args, **kwargs):
            nonlocal failed
            real_atomic(path, *args, **kwargs)
            if path == self.state_path() and not failed:
                failed = True
                raise OSError("failure after final state rename")
        with patch.object(dns_pull, "atomic_write", side_effect=atomic):
            result, _, errors = self.invoke()
        self.assertEqual(result, 6)
        self.assertIn("restored", errors)
        self.assertEqual(self.state_path().read_bytes(), old_state)
        for name, data in old_targets.items():
            self.assertEqual((self.destination / name).read_bytes(), data)
        latest = sorted(self.backups.glob("backup-*"))[-1]
        self.assertEqual((latest / dns_pull.STATE_NAME).read_bytes(), old_state)

    def test_final_new_state_failure_removes_state_and_new_targets(self):
        real_atomic = dns_pull.atomic_write
        def atomic(path, *args, **kwargs):
            real_atomic(path, *args, **kwargs)
            if path == self.state_path():
                raise OSError("failure after state write")
        with patch.object(dns_pull, "atomic_write", side_effect=atomic):
            self.assertEqual(self.invoke()[0], 6)
        self.assertEqual(list(self.destination.iterdir()), [])
        self.assertFalse(self.state_path().exists())

    def test_rollback_failure_is_reported_separately_without_raw_errors(self):
        self.write_existing()
        calls = 0
        real_atomic = dns_pull.atomic_write
        def atomic(path, *args, **kwargs):
            nonlocal calls
            calls += 1
            if calls >= 2:
                raise OSError("SECRET remote/path \x1b[31m")
            return real_atomic(path, *args, **kwargs)
        with patch.object(dns_pull, "atomic_write", side_effect=atomic):
            result, _, errors = self.invoke()
        self.assertEqual(result, 7)
        self.assertIn("rollback incomplete", errors)
        self.assertIn("Administrator recovery", errors)
        self.assertNotIn("SECRET", errors)
        self.assertNotIn("\x1b", errors)

    def test_external_master_change_during_validation_is_not_overwritten(self):
        self.write_existing()
        real_read = dns_pull.read_regular
        reads = 0
        name = next(iter(self.zones))
        def read(path, *args, **kwargs):
            nonlocal reads
            if path == self.destination / name:
                reads += 1
                if reads == 2:
                    path.write_bytes(b"administrator edit")
            return real_read(path, *args, **kwargs)
        with patch.object(dns_pull, "read_regular", side_effect=read):
            result, _, errors = self.invoke()
        self.assertEqual(result, 5)
        self.assertIn("changed during", errors)
        self.assertEqual((self.destination / name).read_bytes(), b"administrator edit")
        self.assertFalse(self.state_path().exists())


if __name__ == "__main__":
    unittest.main()
