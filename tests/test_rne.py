from __future__ import annotations

import unittest

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
