from __future__ import annotations

import asyncio
import json
import sys
import tempfile
import time
import unittest
from pathlib import Path

# Allow running as: python tests/test_osinter.py
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from osinter.base import Finding, OSINTModule
from osinter.executor import OSINTExecutor, detect_target_type


class SleepModule(OSINTModule):
    def __init__(self, name: str, *, delay: float, target_types: list[str]):
        self.name = name
        self.description = "test module"
        self.target_types = target_types
        self.delay = delay

    def validate(self, target: str) -> bool:
        return True

    async def execute(self, target: str, target_type: str) -> list[Finding]:
        await asyncio.sleep(self.delay)
        return [
            Finding(
                source=self.name,
                target=target,
                target_type=target_type,
                data={"ok": True},
                confidence=0.9,
            )
        ]


class TestTargetDetection(unittest.TestCase):
    def test_detect_ip(self):
        self.assertEqual(detect_target_type("8.8.8.8"), "ip")

    def test_detect_email(self):
        self.assertEqual(detect_target_type("user@example.com"), "email")

    def test_detect_domain(self):
        self.assertEqual(detect_target_type("example.com"), "domain")

    def test_detect_username(self):
        self.assertEqual(detect_target_type("github"), "username")


class TestExecutor(unittest.TestCase):
    def test_concurrent_execution(self):
        modules = [
            SleepModule("m1", delay=0.15, target_types=["username"]),
            SleepModule("m2", delay=0.15, target_types=["username"]),
        ]
        ex = OSINTExecutor(modules, semaphore=10)

        start = time.monotonic()
        findings = asyncio.run(ex.scan("github"))
        elapsed = time.monotonic() - start

        self.assertEqual(len(findings), 2)
        # Sequential would be ~0.30s. Concurrent should be noticeably faster.
        self.assertLess(elapsed, 0.28)

    def test_batch_scanning(self):
        modules = [SleepModule("m1", delay=0.01, target_types=["username"])]
        ex = OSINTExecutor(modules, semaphore=10)
        targets = ["alice", "bob", "charlie"]
        findings = asyncio.run(ex.scan_many(targets))
        self.assertEqual(len(findings), 3)
        self.assertEqual({f.target for f in findings}, set(targets))

    def test_export_json_and_csv(self):
        findings = [
            Finding(
                source="dns",
                target="example.com",
                target_type="domain",
                data={"ips": ["93.184.216.34"]},
                confidence=0.99,
            )
        ]
        with tempfile.TemporaryDirectory() as d:
            p_json = Path(d) / "results.json"
            p_csv = Path(d) / "results.csv"

            OSINTExecutor.export_json(findings, p_json)
            OSINTExecutor.export_csv(findings, p_csv)

            payload = json.loads(p_json.read_text(encoding="utf-8"))
            self.assertIsInstance(payload, list)
            self.assertEqual(payload[0]["source"], "dns")

            csv_text = p_csv.read_text(encoding="utf-8")
            self.assertIn("source,target,target_type", csv_text)


if __name__ == "__main__":
    unittest.main(verbosity=2)

