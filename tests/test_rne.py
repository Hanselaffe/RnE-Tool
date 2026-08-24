from __future__ import annotations

import subprocess
import unittest
from unittest.mock import Mock, patch

import rne


class RnETests(unittest.TestCase):
    def test_private_target_allowed_by_default(self) -> None:
        self.assertEqual(rne.validate_target("192.168.1.10"), "192.168.1.10")

    def test_public_target_requires_explicit_allow_public(self) -> None:
        with self.assertRaises(ValueError):
            rne.validate_target("8.8.8.8")
        self.assertEqual(rne.validate_target("8.8.8.8", allow_public=True), "8.8.8.8")

    def test_hostname_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            rne.validate_target("example.com")

    def test_run_nmap_uses_fixed_argument_list_without_shell(self) -> None:
        completed = Mock()
        completed.returncode = 0
        completed.stdout = "<?xml version='1.0'?><nmaprun></nmaprun>"
        completed.stderr = ""

        with patch("rne.subprocess.run", return_value=completed) as run_mock:
            self.assertEqual(rne.run_nmap_scan("192.168.1.10", timeout=12), [])

        run_mock.assert_called_once_with(
            [
                "nmap",
                "-sV",
                "--version-light",
                "-T3",
                "--top-ports",
                "100",
                "-oX",
                "-",
                "192.168.1.10",
            ],
            capture_output=True,
            text=True,
            timeout=12,
            check=False,
        )

    def test_missing_nmap_is_normalized(self) -> None:
        with patch("rne.subprocess.run", side_effect=FileNotFoundError("nmap.exe missing")):
            with self.assertRaisesRegex(RuntimeError, "nmap executable was not found"):
                rne.run_nmap_scan("192.168.1.10")

    def test_parse_nmap_xml_returns_only_open_ports(self) -> None:
        xml_text = """<?xml version='1.0'?>
<nmaprun><host><ports>
<port protocol='tcp' portid='22'><state state='open'/><service name='ssh' product='OpenSSH' version='9.0'/></port>
<port protocol='tcp' portid='80'><state state='closed'/><service name='http'/></port>
</ports></host></nmaprun>"""
        self.assertEqual(
            rne.parse_nmap_xml(xml_text),
            [rne.ServiceFinding(port=22, protocol="tcp", service="ssh", product="OpenSSH", version="9.0")],
        )

    def test_parse_nvd_response_v2(self) -> None:
        payload = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2026-0001",
                        "descriptions": [
                            {"lang": "de", "value": "Beschreibung"},
                            {"lang": "en", "value": "Example description"},
                        ],
                    }
                }
            ]
        }
        self.assertEqual(
            rne.parse_nvd_response(payload),
            [{"id": "CVE-2026-0001", "description": "Example description"}],
        )

    def test_report_states_read_only_boundary(self) -> None:
        report = rne.build_report("127.0.0.1", [], {})
        self.assertIn("No exploit execution", report["note"])


if __name__ == "__main__":
    unittest.main()
