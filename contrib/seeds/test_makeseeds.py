#!/usr/bin/env python3
# Copyright (c) 2026 The Tidecoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Offline regression tests for Tidecoin seed selection and header generation."""

import ipaddress
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import makeseeds


def crawler_line(address, agent, *, services="40d", blocks=3000000, uptime=99, good=1):
    return (f'{address} {good} 1791280800 99% 99% 99% 99% {uptime}% '
            f'{blocks} {services} 70015 "{agent}"\n')


class SeedAgentTest(unittest.TestCase):
    def test_supported_agents(self):
        # Derived from current UA_NAME/CLIENT_VERSION and the legacy 0.18.3 sources.
        for agent in (
            "/Tidecoin:1.0.0/",
            "/TidecoinCore:0.18.3/",
            "/Tidecoin:1.0.0(node one; archive)/",
            "/TidecoinCore:0.18.3(legacy node; operator@example.test)/",
            "/Tidecoin:1.0.0()/",
        ):
            with self.subTest(agent=agent):
                self.assertIsNotNone(makeseeds.PATTERN_AGENT.fullmatch(agent))

    def test_other_agents_and_malformed_versions(self):
        for agent in (
            "/Satoshi:29.0.0/",
            "/Satoshi:0.18.3/",
            "/Other:1.0.0/",
            "/TidecoinCore:0.18.2/",
            "/TidecoinCore:0.18.30/",
            "/Tidecoin:1.0.00/",
            "/Tidecoin:1x0x0/",
            "/Tidecoin:1.0.0evil/",
            "/Tidecoin:1.0.0/extra",
            "/Tidecoin:1.0.0/\n",
            "/Tidecoin:1.0.0(unclosed/",
            "/Tidecoin:1.0.0(other/agent)/",
            "Tidecoin:1.0.0",
        ):
            with self.subTest(agent=agent):
                self.assertIsNone(makeseeds.PATTERN_AGENT.fullmatch(agent))

    def test_parser_preserves_comments(self):
        for agent in (
            "/Tidecoin:1.0.0/",
            "/TidecoinCore:0.18.3/",
            "/Tidecoin:1.0.0(node one; node two)/",
            "/TidecoinCore:0.18.3(legacy node; backup)/",
        ):
            with self.subTest(agent=agent):
                parsed = makeseeds.parseline(crawler_line("1.1.1.1:8755", agent))
                self.assertEqual(parsed["agent"], agent)
                self.assertEqual(parsed["service"], 0x40d)
                self.assertEqual(parsed["port"], 8755)

    def test_parser_rejects_incomplete_agent_field(self):
        prefix = crawler_line("1.1.1.1:8755", "/Tidecoin:1.0.0/").split('"')[0]
        for line in (prefix, prefix + '"', prefix + '"/Tidecoin:1.0.0/',
                     prefix + '/Tidecoin:1.0.0/', "", "# comment\n"):
            with self.subTest(line=line):
                self.assertIsNone(makeseeds.parseline(line))

    def test_seed_selection_and_header_generation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            asmap = makeseeds.ASMap([
                (makeseeds.net_to_prefix(ipaddress.ip_network(f"{i}.0.0.0/8")), 64511 + i)
                for i in range(1, 5)
            ])
            (root / "asmap.dat").write_bytes(asmap.to_binary())
            fixtures = [
                crawler_line("1.1.1.1:8755", "/Tidecoin:1.0.0/"),
                crawler_line("1.1.1.2:8755", "/Tidecoin:1.0.0(node one; archive)/"),
                crawler_line("2.1.1.1:8755", "/TidecoinCore:0.18.3/"),
                crawler_line("2.1.1.2:8755", "/TidecoinCore:0.18.3(legacy node)/"),
                crawler_line("3.1.1.1:8755", "/Satoshi:29.0.0/"),
                crawler_line("3.1.1.2:8755", "/Tidecoin:1.0.0/", services="0"),
                crawler_line("3.1.1.3:8755", "/TidecoinCore:0.18.3/", blocks=999),
                crawler_line("3.1.1.4:8755", "/Tidecoin:1.0.0/", uptime=50),
                crawler_line("3.1.1.5:8755", "/TidecoinCore:0.18.3/", good=0),
                crawler_line("3.1.1.6:8755", "/Tidecoin:1.0.0/extra"),
            ]
            (root / "crawler.txt").write_text("".join(fixtures), encoding="utf8")
            result = subprocess.run([
                sys.executable, str(Path(makeseeds.__file__)),
                "-a", str(root / "asmap.dat"), "-s", str(root / "crawler.txt"),
                "-m", "1000",
            ], check=True, capture_output=True, text=True)
            self.assertEqual(result.stdout.splitlines(), [
                "1.1.1.1:8755 # AS64512",
                "1.1.1.2:8755 # AS64512",
                "2.1.1.1:8755 # AS64513",
                "2.1.1.2:8755 # AS64513",
            ])
            (root / "nodes_main.txt").write_text(result.stdout, encoding="utf8")
            (root / "nodes_test.txt").write_text("", encoding="utf8")
            generated = subprocess.run([
                sys.executable, str(Path(makeseeds.__file__).with_name("generate-seeds.py")), str(root),
            ], check=True, capture_output=True, text=True).stdout
            self.assertIn("chainparams_seed_main", generated)
            self.assertIn("chainparams_seed_test", generated)
            entries = [line.strip() for line in generated.splitlines() if line.startswith("    0x")]
            self.assertEqual(entries, [
                "0x01,0x04,0x01,0x01,0x01,0x01,0x22,0x33,",
                "0x01,0x04,0x01,0x01,0x01,0x02,0x22,0x33,",
                "0x01,0x04,0x02,0x01,0x01,0x01,0x22,0x33,",
                "0x01,0x04,0x02,0x01,0x01,0x02,0x22,0x33,",
            ])


if __name__ == "__main__":
    unittest.main()
