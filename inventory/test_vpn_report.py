import os
import shutil
import tempfile
from pathlib import Path
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.db import connection
from django.test import TestCase, override_settings
from django.test.utils import CaptureQueriesContext
from django.urls import reverse

from .exporters import build_exports
from .models import Configuration, Host, Site
from .vpn_report import build_vpn_report, parse_ccd


class VpnReportFixture:
    def setUp(self):
        self.config = Configuration.load()
        self.alpha = Host.objects.create(
            name="alpha", site=Site.objects.get(pk=1), row=2, column=3, vpn=True,
        )
        self.root = Path(tempfile.mkdtemp(dir=Path.cwd(), prefix=".vpn-test-"))
        self.addCleanup(shutil.rmtree, self.root)
        self.ccd = self.root / "ccd"
        self.ccd.mkdir()
        (self.ccd / "alpha").write_text("ifconfig-push 172.28.1.50 255.255.0.0\n")
        (self.ccd / "DEFAULT").write_text("disable\n")

    def report(self, **kwargs):
        kwargs.setdefault("ccd_dir", self.ccd)
        return build_vpn_report(**kwargs)


class VpnReportTests(VpnReportFixture, TestCase):
    def test_ccd_parser_ignores_comments_and_other_directives(self):
        self.assertEqual(parse_ccd(
            "# ifconfig-push 1.2.3.4 255.255.0.0\n"
            "; ifconfig-push 1.2.3.4 255.255.0.0\n"
            'push "route 10.0.0.0 255.0.0.0"\n'
            "ifconfig-push 172.28.1.50 255.255.0.0\n",
        ), [["172.28.1.50", "255.255.0.0"]])

    def test_clean_ccd_and_default_ignored(self):
        report = self.report()
        self.assertEqual(report["status"], "clean")
        self.assertTrue(report["aligned"])
        self.assertEqual(report["issue_count"], 0)
        self.assertEqual(report["ccd_orphans"], [])
        self.assertEqual(report["rows"][0]["ccd_value"], "172.28.1.50 255.255.0.0")

    def test_ccd_mismatch_missing_invalid_and_duplicate(self):
        cases = [
            ("ifconfig-push 172.28.9.9 255.255.0.0\n", "pushes 172.28.9.9, expected 172.28.1.50"),
            ("ifconfig-push 172.28.1.50\n", "malformed ifconfig-push"),
            ("ifconfig-push bad 255.255.0.0\n", "malformed ifconfig-push"),
            ("ifconfig-push 172.28.1.50 bad\n", "malformed ifconfig-push"),
            ("ifconfig-push 172.28.1.50 255.255.0.0 extra\n", "malformed ifconfig-push"),
            ("ifconfig-push 172.28.1.50 255.255.0.0\n" * 2, "2 ifconfig-push directives"),
            ("# disabled\n", "no ifconfig-push directive"),
        ]
        for text, issue in cases:
            with self.subTest(issue=issue):
                (self.ccd / "alpha").write_text(text)
                report = self.report()
                self.assertEqual(report["status"], "issues")
                self.assertIn(issue, report["rows"][0]["issues"][0])
        (self.ccd / "alpha").unlink()
        self.assertEqual(self.report()["rows"][0]["issues"], ["CCD file alpha is missing."])

    def test_orphan_files_and_nonmembers_are_reported(self):
        Host.objects.create(name="lan", site=Site.objects.get(pk=1), row=1, column=0)
        (self.ccd / "lan").write_text("ifconfig-push 172.28.1.1 255.255.0.0\n")
        (self.ccd / "ghost").write_text("")
        (self.ccd / "subdir").mkdir()
        report = self.report()
        self.assertEqual(report["ccd_orphans"], [
            {"name": "ghost", "regular_file": True},
            {"name": "lan", "regular_file": True},
            {"name": "subdir", "regular_file": False},
        ])
        self.assertEqual(report["issue_count"], 3)
        self.assertEqual(len(report["rows"]), 1)

    def test_source_errors_are_inconclusive_not_clean_or_missing_members(self):
        for source in (self.root / "absent", self.ccd / "alpha"):
            with self.subTest(source=source):
                report = self.report(ccd_dir=source)
                self.assertEqual(report["status"], "inconclusive")
                self.assertFalse(report["aligned"])
                self.assertTrue(report["sources"][0]["error"])
                self.assertEqual(report["rows"][0]["ccd_value"], "(not checked)")
                self.assertEqual(report["rows"][0]["issues"], [])
                self.assertFalse(report["rows"][0]["checked"])
        with patch("inventory.vpn_report.os.scandir", side_effect=PermissionError(13, "Permission denied")):
            self.assertIn("Permission denied", self.report()["sources"][0]["error"])
        self.assertEqual(self.report(ccd_dir="bad\x00path")["status"], "inconclusive")

    def test_file_read_failure_and_truncation_are_inconclusive(self):
        real_open = os.open

        def denied(path, *args, **kwargs):
            if path == "alpha":
                raise PermissionError(13, "Permission denied")
            return real_open(path, *args, **kwargs)

        with patch("inventory.vpn_report.os.open", side_effect=denied):
            report = self.report()
        self.assertEqual(report["status"], "inconclusive")
        self.assertIn("Permission denied", report["rows"][0]["issues"][0])
        with patch("inventory.vpn_report.MAX_FILE_BYTES", 8):
            self.assertEqual(self.report()["status"], "inconclusive")
        with patch("inventory.vpn_report.MAX_TOTAL_BYTES", 8):
            self.assertEqual(self.report()["status"], "inconclusive")
        (self.ccd / "alpha").write_bytes(b"\xff")
        self.assertEqual(self.report()["status"], "inconclusive")

    def test_directory_scan_is_bounded(self):
        with patch("inventory.vpn_report.MAX_DIRECTORY_ENTRIES", 1):
            report = self.report()
        self.assertEqual(report["status"], "inconclusive")
        self.assertIn("more than 1 entries", report["sources"][0]["error"])
        self.assertEqual(report["ccd_orphans"], [])

    def test_symlinks_fifo_and_symlink_directory_are_not_followed(self):
        (self.ccd / "alpha").unlink()
        (self.ccd / "alpha").symlink_to(self.root / "absent")
        self.assertEqual(self.report()["status"], "inconclusive")
        (self.ccd / "alpha").unlink()
        os.mkfifo(self.ccd / "alpha")
        real_open = os.open

        def no_special_open(path, *args, **kwargs):
            self.assertNotEqual(path, "alpha")
            return real_open(path, *args, **kwargs)

        with patch("inventory.vpn_report.os.open", side_effect=no_special_open):
            self.assertEqual(self.report()["status"], "inconclusive")
        link = self.root / "link"
        link.symlink_to(self.ccd, target_is_directory=True)
        self.assertEqual(self.report(ccd_dir=link)["status"], "inconclusive")
        self.assertEqual(self.report(ccd_dir=link / "child")["status"], "inconclusive")

    def test_report_only_opens_ccd_read_only_without_database_writes(self):
        before = (self.ccd / "alpha").read_bytes(), (self.ccd / "alpha").stat().st_mtime_ns
        real_open = os.open
        opened = []

        def recording(path, flags, *args, **kwargs):
            opened.append((path, flags))
            self.assertFalse(flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC))
            return real_open(path, flags, *args, **kwargs)

        forbidden = AssertionError("write or external command invoked")
        with CaptureQueriesContext(connection) as queries, \
                patch("inventory.vpn_report.os.open", side_effect=recording), \
                patch("subprocess.run", side_effect=forbidden), \
                patch.object(Path, "write_text", side_effect=forbidden), \
                patch.object(Path, "write_bytes", side_effect=forbidden):
            for _ in range(2):
                self.report()
        self.assertTrue(opened)
        self.assertFalse(any("hosts" in str(path) for path, _ in opened))
        self.assertFalse(any(q["sql"].lstrip().upper().startswith(("UPDATE", "INSERT", "DELETE"))
                             for q in queries))
        self.assertEqual(before, (
            (self.ccd / "alpha").read_bytes(), (self.ccd / "alpha").stat().st_mtime_ns,
        ))

    def test_vpn_forward_and_reverse_export_preserved(self):
        exports = build_exports()
        self.assertIn("alpha.vpn. 300 A 172.28.1.50", exports["vpn.zone"])
        self.assertIn("50.1.28.172.in-addr.arpa. 300 PTR alpha.vpn.", exports["reverse-vpn.zone"])
        self.assertNotIn("vpn.hosts", exports)


class VpnReportViewTests(VpnReportFixture, TestCase):
    def setUp(self):
        super().setUp()
        self.user = get_user_model().objects.create_user(username="operator", is_staff=True)
        self.client.force_login(self.user)
        overrides = override_settings(DNSGRID_VPN_CCD_DIR=str(self.ccd))
        overrides.enable()
        self.addCleanup(overrides.disable)

    def test_page_and_export_states_real_link_and_read_only_repeated_gets(self):
        forbidden = AssertionError("write, validator, or reload invoked")
        before = Configuration.objects.values().get(pk=1)
        states = [
            ("clean", "no discrepancies found"),
            ("issues", "VPN alignment warning"),
            ("inconclusive", "VPN alignment check inconclusive"),
        ]
        for state, advisory in states:
            if state == "issues":
                (self.ccd / "alpha").write_text("ifconfig-push 172.28.9.9 255.255.0.0\n")
            if state == "inconclusive":
                (self.ccd / "alpha").unlink()
                (self.ccd / "alpha").symlink_to(self.root / "absent")
            with self.subTest(state=state), CaptureQueriesContext(connection) as queries, \
                    patch("subprocess.run", side_effect=forbidden), \
                    patch.object(Path, "write_text", side_effect=forbidden), \
                    patch.object(Path, "write_bytes", side_effect=forbidden):
                for _ in range(2):
                    response = self.client.get(reverse("exports"))
                    self.assertContains(response, advisory)
                    self.assertContains(response, 'role="status"')
                    self.assertContains(response, f'href="{reverse("vpn-report")}"')
                    self.assertEqual(response.context["vpn_report"]["status"], state)
                    self.assertContains(response, "alpha.vpn. 300 A 172.28.1.50")
                    self.assertNotContains(response, "/etc/hosts")
                    self.assertNotContains(response, "Hosts file")
                    report = self.client.get(reverse("vpn-report"))
                    self.assertEqual(report.context["report"]["status"], state)
                    self.assertContains(report, "read-only")
                    self.assertNotContains(report, "hosts file")
            for query in queries:
                statement = query["sql"].lstrip()
                if statement.upper().startswith(("UPDATE", "INSERT", "DELETE")):
                    self.assertRegex(
                        statement,
                        r'^UPDATE "inventory_configuration" SET "revision" = '
                        r'"inventory_configuration"\."revision" WHERE '
                        r'"inventory_configuration"\."id" = 1$',
                    )
        self.assertEqual(Configuration.objects.values().get(pk=1), before)

    def test_export_uses_same_materialized_objects_for_report_and_artifacts(self):
        from .vpn_report import build_vpn_report as real_report
        from .exporters import build_exports as real_exports
        snapshots = {}

        def exports(*args, **kwargs):
            snapshots["exports"] = kwargs
            return real_exports(*args, **kwargs)

        def report(*args, **kwargs):
            snapshots["report"] = kwargs
            return real_report(*args, **kwargs)

        with CaptureQueriesContext(connection) as queries, \
                patch("inventory.views.build_exports", side_effect=exports), \
                patch("inventory.vpn_report.build_vpn_report", side_effect=report):
            response = self.client.get(reverse("exports"))
            self.assertEqual(response.status_code, 200)
            self.assertContains(response, "JSON v2")
            self.assertContains(response, "static protection does not block an archive replacement")
        self.assertIs(snapshots["exports"]["config"], snapshots["report"]["config"])
        self.assertIs(snapshots["exports"]["hosts"], snapshots["report"]["hosts"])
        statements = [query["sql"] for query in queries]
        lock = next(index for index, sql in enumerate(statements)
                    if sql.startswith('UPDATE "inventory_configuration"'))
        config_read = next(index for index, sql in enumerate(statements)
                           if sql.startswith("SELECT") and '"inventory_configuration"' in sql)
        hosts_read = next(index for index, sql in enumerate(statements)
                          if sql.startswith("SELECT") and '"inventory_host"' in sql)
        self.assertLess(lock, config_read)
        self.assertLess(config_read, hosts_read)

    def test_warning_is_nonblocking_and_stale_download_still_rejected(self):
        Configuration.objects.filter(pk=1).update(dns_export_directory=str(self.root))
        revision = self.config.revision
        for state in ("clean", "issues", "inconclusive"):
            if state == "issues":
                (self.ccd / "alpha").unlink()
            if state == "inconclusive":
                shutil.rmtree(self.ccd)
            response = self.client.get(reverse("exports"))
            self.assertEqual(response.context["vpn_report"]["status"], state)
            if state != "clean":
                self.assertContains(response, "does not block downloads or publication")
            self.assertContains(response, f'action="{reverse("dns-publish")}"')
            with patch("subprocess.run", side_effect=AssertionError("unexpected command")):
                for name in ("vpn.zone", "reverse-vpn.zone", "forward.zone"):
                    self.assertEqual(self.client.get(
                        reverse("download", args=[name]), {"revision": revision},
                    ).status_code, 200)
                self.assertEqual(self.client.get(
                    reverse("download", args=["vpn.zone"]), {"revision": revision + 1},
                ).status_code, 409)
            with patch("inventory.views.publish_dns_zones", return_value=([], [])) as publish:
                self.assertEqual(self.client.post(
                    reverse("dns-publish"), {"revision": revision},
                ).status_code, 302)
                publish.assert_called_once_with(str(revision))

    def test_post_is_rejected_and_access_requires_operator(self):
        self.assertEqual(self.client.post(reverse("vpn-report")).status_code, 405)
        self.user.is_staff = False
        self.user.save()
        self.assertEqual(self.client.get(reverse("vpn-report")).status_code, 403)
