from __future__ import annotations

import unittest
from unittest.mock import patch

import rne
from rne_core import preflight


class ToolchainPreflightTests(unittest.TestCase):
    @patch("rne_core.preflight._probe")
    @patch("rne_core.preflight.shutil.which")
    def test_nmap_ready_when_required_capabilities_are_present(self, which_mock, probe_mock) -> None:
        which_mock.return_value = "C:/Program Files/Nmap/nmap.exe"
        probe_mock.side_effect = [
            (0, "Nmap version 7.95"),
            (0, "-sV --version-light --top-ports -oX -6 --script"),
        ]
        result = preflight.diagnose_nmap()
        self.assertTrue(result.installed)
        self.assertTrue(result.ready)
        self.assertEqual(result.version, "7.95")
        self.assertEqual(result.issues, ())

    @patch("rne_core.preflight._probe")
    @patch("rne_core.preflight.shutil.which")
    def test_searchsploit_detects_missing_json_capability(self, which_mock, probe_mock) -> None:
        which_mock.return_value = "C:/tools/searchsploit.exe"
        probe_mock.return_value = (0, "SearchSploit 4.0\n-m, --mirror")
        result = preflight.diagnose_searchsploit()
        self.assertTrue(result.installed)
        self.assertFalse(result.ready)
        self.assertFalse(result.capabilities["json_-j"])
        self.assertIn("missing required CLI capabilities", result.issues[0])

    @patch("rne_core.preflight._probe")
    @patch("rne_core.preflight.shutil.which")
    def test_gobuster_checks_dir_adapter_flags(self, which_mock, probe_mock) -> None:
        which_mock.return_value = "C:/tools/gobuster.exe"
        probe_mock.side_effect = [
            (0, "gobuster version 3.8.2"),
            (0, "Usage: gobuster dir -u --url -w --wordlist --threads --timeout --no-progress --no-error --quiet"),
        ]
        result = preflight.diagnose_gobuster()
        self.assertTrue(result.ready)
        self.assertEqual(result.version, "3.8.2")
        self.assertTrue(all(result.capabilities.values()))

    @patch("rne_core.preflight.shutil.which", return_value=None)
    def test_missing_tool_is_reported_without_probe(self, _which_mock) -> None:
        result = preflight.diagnose_nmap()
        self.assertFalse(result.installed)
        self.assertFalse(result.ready)
        self.assertIn("not found", result.issues[0])

    @patch("rne.toolchain_diagnostics")
    def test_verbose_cli_prints_readiness(self, diagnostics_mock) -> None:
        diagnostics_mock.return_value = {
            "nmap": preflight.ToolDiagnostic("nmap", True, "C:/nmap.exe", "7.95", True, {"-sV": True}),
            "searchsploit": preflight.ToolDiagnostic("searchsploit", False, issues=("executable not found on PATH",)),
            "gobuster": preflight.ToolDiagnostic("gobuster", False, issues=("executable not found on PATH",)),
        }
        with patch("builtins.print") as print_mock:
            self.assertEqual(rne.main(["status", "--verbose"]), 0)
        rendered = "\n".join(" ".join(str(arg) for arg in call.args) for call in print_mock.call_args_list)
        self.assertIn("scan_pipeline_ready: yes", rendered)
        self.assertIn("version: 7.95", rendered)


if __name__ == "__main__":
    unittest.main()
