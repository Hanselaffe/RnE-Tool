from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import rne
from rne_core.models import CveCandidate, ExploitCandidate, ServiceFinding, WebFinding
from rne_core.orchestrator import OrchestrationOptions, run_assessment
from rne_core.scope import ScopePolicy, validate_target
from rne_core import tools


class ScopeTests(unittest.TestCase):
    def test_active_assessment_requires_authorization(self) -> None:
        with self.assertRaisesRegex(ValueError, "authorized"):
            validate_target("192.168.56.10", ScopePolicy(authorized=False))

    def test_public_target_requires_second_gate(self) -> None:
        with self.assertRaisesRegex(ValueError, "allow-public"):
            validate_target("8.8.8.8", ScopePolicy(authorized=True))
        self.assertEqual(
            validate_target("8.8.8.8", ScopePolicy(authorized=True, allow_public=True)),
            "8.8.8.8",
        )

    def test_hostname_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "literal"):
            validate_target("example.com", ScopePolicy(authorized=True))


class NmapTests(unittest.TestCase):
    def test_profiles_build_fixed_argument_lists(self) -> None:
        self.assertEqual(
            tools.build_nmap_command("192.168.56.10", "quick"),
            ["nmap", "-sV", "--version-light", "-T3", "--top-ports", "100", "-oX", "-", "192.168.56.10"],
        )
        self.assertEqual(
            tools.build_nmap_command("192.168.56.10", "standard"),
            ["nmap", "-sV", "-T3", "--top-ports", "1000", "-oX", "-", "192.168.56.10"],
        )
        self.assertEqual(
            tools.build_nmap_command("192.168.56.10", "deep", nse_vuln=True),
            ["nmap", "-sV", "-T3", "-p-", "--script", "vuln", "-oX", "-", "192.168.56.10"],
        )

    def test_ipv6_target_enables_nmap_ipv6_mode(self) -> None:
        self.assertEqual(
            tools.build_nmap_command("2001:db8::10", "quick")[:3],
            ["nmap", "-6", "-sV"],
        )

    @patch("rne_core.tools.subprocess.run")
    def test_external_commands_never_use_shell(self, run_mock) -> None:
        run_mock.return_value = SimpleNamespace(returncode=0, stdout="<?xml version='1.0'?><nmaprun></nmaprun>", stderr="")
        tools.run_nmap("192.168.56.10", "quick", timeout=30)
        self.assertFalse(run_mock.call_args.kwargs["shell"])
        self.assertEqual(run_mock.call_args.kwargs["timeout"], 30)

    def test_nmap_xml_normalizes_open_services(self) -> None:
        xml_text = """<?xml version='1.0'?>
<nmaprun><host><ports>
<port protocol='tcp' portid='22'><state state='open'/><service name='ssh' product='OpenSSH' version='9.6'/></port>
<port protocol='tcp' portid='80'><state state='closed'/><service name='http'/></port>
<port protocol='tcp' portid='443'><state state='open'/><service name='https' product='nginx' version='1.24' tunnel='ssl'/></port>
</ports></host></nmaprun>"""
        findings = tools.parse_nmap_xml(xml_text)
        self.assertEqual([item.port for item in findings], [22, 443])
        self.assertEqual(findings[0].product, "OpenSSH")
        self.assertTrue(findings[1].is_web)


class CorrelationTests(unittest.TestCase):
    @patch("rne_core.tools._run")
    def test_searchsploit_json_is_normalized(self, run_mock) -> None:
        run_mock.return_value = SimpleNamespace(
            stdout=json.dumps(
                {
                    "RESULTS_EXPLOIT": [
                        {"EDB-ID": "12345", "Title": "Example", "Path": "exploits/linux/remote/12345.py", "Type": "remote", "Platform": "linux"}
                    ]
                }
            )
        )
        candidates, command = tools.search_exploit_db("OpenSSH", "9.6")
        self.assertEqual(command, ["searchsploit", "-j", "OpenSSH", "9.6"])
        self.assertEqual(candidates[0].edb_id, "12345")
        self.assertEqual(candidates[0].title, "Example")

    def test_nvd_v2_parser_is_bounded(self) -> None:
        payload = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": f"CVE-2026-{index:04d}",
                        "published": "2026-01-01T00:00:00.000",
                        "lastModified": "2026-01-02T00:00:00.000",
                        "descriptions": [{"lang": "en", "value": f"Description {index}"}],
                    }
                }
                for index in range(1, 8)
            ]
        }
        results = tools.parse_nvd_response(payload, limit=3)
        self.assertEqual(len(results), 3)
        self.assertEqual(results[0].cve_id, "CVE-2026-0001")

    @patch.dict("os.environ", {}, clear=True)
    def test_nvd_budget_without_api_key_is_five(self) -> None:
        self.assertEqual(tools.nvd_request_budget(), 5)

    @patch.dict("os.environ", {"NVD_API_KEY": "test-key"}, clear=True)
    def test_nvd_budget_with_api_key_is_fifty(self) -> None:
        self.assertEqual(tools.nvd_request_budget(), 50)

    def test_web_url_uses_discovered_service(self) -> None:
        finding = ServiceFinding(8443, "tcp", "open", "https", "nginx", "1.24", "ssl")
        self.assertEqual(tools.build_web_url("192.168.56.10", finding), "https://192.168.56.10:8443/")


class OrchestratorTests(unittest.TestCase):
    @patch("rne_core.orchestrator.nvd_request_budget", return_value=5)
    @patch("rne_core.orchestrator.run_gobuster")
    @patch("rne_core.orchestrator.search_nvd")
    @patch("rne_core.orchestrator.search_exploit_db")
    @patch("rne_core.orchestrator.run_nmap")
    @patch("rne_core.orchestrator.toolchain_status")
    def test_pipeline_correlates_discovered_services(
        self,
        status_mock,
        nmap_mock,
        exploit_mock,
        nvd_mock,
        gobuster_mock,
        _budget_mock,
    ) -> None:
        service = ServiceFinding(443, "tcp", "open", "https", "nginx", "1.24", "ssl")
        status_mock.return_value = {"nmap": True, "searchsploit": True, "gobuster": True}
        nmap_mock.return_value = ([service], ["nmap", "..."])
        exploit_mock.return_value = ([ExploitCandidate("12345", "Candidate")], ["searchsploit", "..."])
        nvd_mock.return_value = [CveCandidate("CVE-2026-0001", "Example")]
        gobuster_mock.return_value = ([WebFinding("https://192.168.56.10/", "/admin (Status: 403)")], ["gobuster", "..."])

        report = run_assessment(
            "192.168.56.10",
            policy=ScopePolicy(authorized=True),
            options=OrchestrationOptions(web_enum=True, wordlist="wordlist.txt"),
        )

        key = service.label
        self.assertEqual(report.services, [service])
        self.assertEqual(report.exploits[key][0].edb_id, "12345")
        self.assertEqual(report.cves[key][0].cve_id, "CVE-2026-0001")
        self.assertEqual(report.web_findings[key][0].output_line, "/admin (Status: 403)")
        self.assertEqual(len(report.executed_commands), 3)

    @patch("rne_core.orchestrator.nvd_request_budget", return_value=1)
    @patch("rne_core.orchestrator.search_nvd", return_value=[])
    @patch("rne_core.orchestrator.search_exploit_db")
    @patch("rne_core.orchestrator.run_nmap")
    @patch("rne_core.orchestrator.toolchain_status")
    def test_nvd_budget_is_enforced_per_run(
        self,
        status_mock,
        nmap_mock,
        exploit_mock,
        nvd_mock,
        _budget_mock,
    ) -> None:
        first = ServiceFinding(22, "tcp", "open", "ssh", "OpenSSH", "9.6")
        second = ServiceFinding(80, "tcp", "open", "http", "nginx", "1.24")
        status_mock.return_value = {"nmap": True, "searchsploit": False, "gobuster": False}
        nmap_mock.return_value = ([first, second], ["nmap", "..."])
        exploit_mock.return_value = ([], [])

        report = run_assessment(
            "192.168.56.10",
            policy=ScopePolicy(authorized=True),
            options=OrchestrationOptions(use_exploit_db=False),
        )

        self.assertEqual(nvd_mock.call_count, 1)
        self.assertIn("NVD correlation limited to 1 service queries", "\n".join(report.warnings))
        self.assertEqual(report.cves[second.label], [])


class MirrorTests(unittest.TestCase):
    def test_mirror_requires_numeric_edb_id(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):
                tools.mirror_exploit("../../evil", directory)

    @patch("rne_core.tools._run")
    def test_mirror_creates_exactly_one_workspace_file(self, run_mock) -> None:
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)

            def fake_run(command, *, timeout, cwd=None):
                self.assertEqual(command, ["searchsploit", "-m", "12345"])
                self.assertEqual(Path(cwd), workspace.resolve())
                (workspace / "12345.py").write_text("# mirrored public exploit\n", encoding="utf-8")
                return SimpleNamespace(stdout="", stderr="", returncode=0)

            run_mock.side_effect = fake_run
            copied, command = tools.mirror_exploit("12345", workspace)
            self.assertEqual(copied.name, "12345.py")
            self.assertEqual(command, ["searchsploit", "-m", "12345"])

    def test_cli_mirror_has_explicit_confirmation_gate(self) -> None:
        self.assertEqual(rne.main(["mirror", "--edb-id", "12345"]), 2)


if __name__ == "__main__":
    unittest.main()
