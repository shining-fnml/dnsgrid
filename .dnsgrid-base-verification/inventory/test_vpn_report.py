import builtins
import os
import shutil
import tempfile
from pathlib import Path
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.urls import reverse

from .exporters import build_exports
from .models import Configuration, Host, Site
from .vpn_report import build_vpn_report, parse_ccd, parse_hosts


HOSTS_FILE = """\
127.0.0.1 localhost
192.168.1.6 lan lan.intranet.example.tld
172.28.1.50 alpha.vpn   # aligned
172.28.2.9 beta.vpn
172.28.1.4 delta.vpn
172.28.1.4 delta.vpn
172.28.1.5 epsilon.vpn
172.28.9.9 ghost.vpn
"""

CCD_FILES = {
    "alpha": "ifconfig-push 172.28.1.50 255.255.0.0\n",
    "beta": "ifconfig-push 172.28.2.2 255.255.0.0\n",
    "gamma": "ifconfig-push 172.28.1.3\n",
    "epsilon": "# ifconfig-push 172.28.1.5 255.255.0.0\npush \"route 10.0.0.0 255.0.0.0\"\n",
    "lan": "ifconfig-push 172.28.1.6 255.255.0.0\n",
    "ghost": "ifconfig-push 172.28.9.9 255.255.0.0\n",
    "DEFAULT": "disable\n",
}


class VpnReportTests(TestCase):
    def setUp(self):
        self.config = Configuration.load()
        site1, site2 = Site.objects.get(pk=1), Site.objects.get(pk=2)
        Host.objects.create(name="alpha", site=site1, row=2, column=3, vpn=True)
        Host.objects.create(name="beta", site=site2, row=1, column=0, vpn=True)
        Host.objects.create(name="gamma", site=site1, row=3, column=0, vpn=True)
        Host.objects.create(name="delta", site=site1, row=4, column=0, vpn=True)
        Host.objects.create(name="epsilon", site=site1, row=5, column=0, vpn=True)
        Host.objects.create(name="lan", site=site1, row=6, column=0, vpn=False)
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root)
        self.hosts_file = self.root / "hosts"
        self.hosts_file.write_text(HOSTS_FILE)
        self.ccd = self.root / "ccd"
        self.ccd.mkdir()
        for name, content in CCD_FILES.items():
            (self.ccd / name).write_text(content)
        (self.ccd / "subdir").mkdir()

    def report(self, **kwargs):
        kwargs.setdefault("hosts_file", self.hosts_file)
        kwargs.setdefault("ccd_dir", self.ccd)
        return build_vpn_report(**kwargs)

    def test_parsers_only_consider_vpn_names_and_active_directives(self):
        entries = parse_hosts(HOSTS_FILE)
        self.assertNotIn("localhost", entries)
        self.assertNotIn("lan", entries)
        self.assertEqual(entries["alpha"], [(3, "172.28.1.50")])
        self.assertEqual(entries["delta"], [(5, "172.28.1.4"), (6, "172.28.1.4")])
        self.assertEqual(parse_ccd(CCD_FILES["alpha"]), [["172.28.1.50", "255.255.0.0"]])
        self.assertEqual(parse_ccd(CCD_FILES["epsilon"]), [])

    def test_mismatches_and_orphans(self):
        report = self.report()
        rows = {row["name"]: row for row in report["rows"]}
        self.assertEqual(sorted(rows), ["alpha", "beta", "delta", "epsilon", "gamma"])
        self.assertEqual(rows["alpha"]["issues"], [])
        self.assertEqual(rows["alpha"]["short_name"], "alpha.vpn")
        self.assertEqual(rows["alpha"]["ccd_value"], "172.28.1.50 255.255.0.0")
        self.assertEqual(rows["beta"]["expected"], "172.28.2.1")
        self.assertEqual(rows["beta"]["issues"], [
            "Hosts-file line 4 maps to 172.28.2.9, expected 172.28.2.1.",
            "CCD file beta pushes 172.28.2.2, expected 172.28.2.1.",
        ])
        self.assertEqual(rows["gamma"]["issues"], [
            "gamma.vpn is missing from the hosts file.",
            "CCD file gamma has a malformed ifconfig-push: '172.28.1.3'.",
        ])
        self.assertEqual(rows["delta"]["issues"], [
            "delta.vpn appears on multiple hosts-file lines (5, 6).",
            "CCD file delta is missing.",
        ])
        self.assertEqual(rows["epsilon"]["issues"], [
            "CCD file epsilon has no ifconfig-push directive.",
        ])
        self.assertEqual(report["hosts_orphans"], [
            {"name": "ghost.vpn", "lines": "8", "addresses": "172.28.9.9"},
        ])
        self.assertEqual(report["ccd_orphans"], [
            {"name": "ghost", "regular_file": True},
            {"name": "lan", "regular_file": True},
            {"name": "subdir", "regular_file": False},
        ])
        self.assertEqual(report["issue_count"], 11)
        self.assertFalse(report["aligned"])

    def test_aligned_inventory(self):
        Host.objects.exclude(name="alpha").delete()
        self.hosts_file.write_text("127.0.0.1 localhost\n172.28.1.50 alpha.vpn\n")
        for path in self.ccd.iterdir():
            if path.name not in ("alpha", "DEFAULT"):
                shutil.rmtree(path) if path.is_dir() else path.unlink()
        report = self.report()
        self.assertTrue(report["aligned"])
        self.assertEqual(report["issue_count"], 0)

    def test_missing_and_unreadable_sources_are_reported_not_treated_as_aligned(self):
        report = self.report(hosts_file=self.root / "absent", ccd_dir=self.root / "nope")
        self.assertEqual([source["error"] for source in report["sources"]], ["missing", "missing"])
        self.assertEqual(report["issue_count"], 2)
        self.assertFalse(report["aligned"])
        for row in report["rows"]:
            self.assertEqual(row["hosts_value"], "(not checked)")
            self.assertEqual(row["ccd_value"], "(not checked)")
            self.assertEqual(row["issues"], [])
        self.assertEqual(report["hosts_orphans"], [])
        self.assertEqual(report["ccd_orphans"], [])
        report = self.report(hosts_file=self.ccd, ccd_dir=self.hosts_file)
        self.assertEqual(
            [source["error"] for source in report["sources"]],
            ["not a regular file", "not a directory"],
        )
        with patch("inventory.vpn_report.os.scandir", side_effect=PermissionError(13, "Permission denied")):
            with patch("builtins.open", side_effect=PermissionError(13, "Permission denied")):
                report = self.report()
        self.assertEqual(
            [source["error"] for source in report["sources"]],
            ["unreadable (Permission denied)", "unreadable (Permission denied)"],
        )

    def test_unreadable_ccd_file_is_reported(self):
        real_open = builtins.open

        def guarded(path, *args, **kwargs):
            if Path(path) == self.ccd / "alpha":
                raise PermissionError(13, "Permission denied")
            return real_open(path, *args, **kwargs)

        with patch("builtins.open", side_effect=guarded):
            report = self.report()
        alpha = next(row for row in report["rows"] if row["name"] == "alpha")
        self.assertEqual(alpha["issues"], ["CCD file alpha is unreadable (Permission denied)."])

    def test_report_is_read_only(self):
        def snapshot():
            return {
                str(path): (path.is_dir() or path.read_bytes(), path.stat().st_mtime_ns)
                for path in sorted(self.root.rglob("*"))
            }

        before = snapshot()
        modes = []
        real_open = builtins.open

        def recording_open(path, mode="r", *args, **kwargs):
            modes.append(mode)
            return real_open(path, mode, *args, **kwargs)

        forbidden = AssertionError("write path invoked")
        with patch("builtins.open", side_effect=recording_open), \
                patch.object(os, "remove", side_effect=forbidden), \
                patch.object(os, "unlink", side_effect=forbidden), \
                patch.object(os, "rename", side_effect=forbidden), \
                patch.object(os, "replace", side_effect=forbidden), \
                patch.object(os, "mkdir", side_effect=forbidden), \
                patch.object(os, "chmod", side_effect=forbidden), \
                patch.object(Path, "write_text", side_effect=forbidden), \
                patch.object(Path, "write_bytes", side_effect=forbidden):
            self.report()
        self.assertTrue(modes)
        self.assertEqual(set(modes), {"rb"})
        self.assertEqual(snapshot(), before)

    def test_vpn_hosts_export_matches_report_expectation(self):
        lines = build_exports()["vpn.hosts"].splitlines()[1:]
        self.assertIn("172.28.1.50 alpha.vpn", lines)
        self.assertNotIn("lan", " ".join(lines))
        for line in lines:
            address, name = line.split()
            self.assertTrue(name.endswith(".vpn"))


class VpnReportViewTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(username="operator", is_staff=True)
        self.client.force_login(self.user)
        Host.objects.create(name="alpha", site=Site.objects.get(pk=1), row=2, column=3, vpn=True)
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root)
        (self.root / "hosts").write_text("172.28.1.9 alpha.vpn\n172.28.9.9 ghost.vpn\n")
        (self.root / "ccd").mkdir()
        (self.root / "ccd" / "ghost").write_text("ifconfig-push 172.28.9.9 255.255.0.0\n")
        overrides = override_settings(
            DNSGRID_VPN_HOSTS_FILE=str(self.root / "hosts"),
            DNSGRID_VPN_CCD_DIR=str(self.root / "ccd"),
        )
        overrides.enable()
        self.addCleanup(overrides.disable)

    def test_page_reports_issues_read_only(self):
        revision = Configuration.load().revision
        response = self.client.get(reverse("vpn-report"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "VPN alignment report")
        self.assertContains(response, "read-only")
        self.assertContains(response, "Hosts-file line 1 maps to 172.28.1.9, expected 172.28.1.50.")
        self.assertContains(response, "CCD file alpha is missing.")
        self.assertContains(response, "ghost.vpn")
        self.assertContains(response, "<code>ghost</code>", html=True)
        self.assertNotContains(response, "<form method=\"post\"")
        self.assertEqual(Configuration.load().revision, revision)
        self.assertEqual(
            (self.root / "hosts").read_text(), "172.28.1.9 alpha.vpn\n172.28.9.9 ghost.vpn\n",
        )
        self.assertFalse((self.root / "ccd" / "alpha").exists())

    def test_post_is_rejected_and_access_requires_operator(self):
        self.assertEqual(self.client.post(reverse("vpn-report")).status_code, 405)
        self.user.is_staff = False
        self.user.save()
        self.assertEqual(self.client.get(reverse("vpn-report")).status_code, 403)

    def test_navigation_and_export_page_link_report_and_keep_vpn_hosts_download(self):
        response = self.client.get(reverse("exports"))
        self.assertContains(response, reverse("vpn-report"))
        self.assertContains(response, "<code>ip name.vpn</code>", html=True)
        revision = response.context["revision"]
        download = self.client.get(
            reverse("download", args=["vpn.hosts"]) + f"?revision={revision}",
        )
        self.assertEqual(download.status_code, 200)
        self.assertIn("172.28.1.50 alpha.vpn\n", download.content.decode())
        self.assertNotIn("vpn.example.tld", download.content.decode())
