from __future__ import annotations

import asyncio
import csv
import ipaddress
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Optional, Sequence

from .base import Finding, OSINTModule


EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}$")


def detect_target_type(target: str) -> str:
    t = target.strip()
    if not t:
        return "username"
    try:
        ipaddress.ip_address(t)
        return "ip"
    except ValueError:
        pass
    if EMAIL_RE.match(t):
        return "email"
    if DOMAIN_RE.match(t.lower()):
        return "domain"
    return "username"


@dataclass(slots=True)
class ScanResult:
    target: str
    target_type: str
    findings: List[Finding]


class OSINTExecutor:
    """
    Orchestrates module selection and concurrent execution.
    """

    def __init__(
        self,
        modules: Sequence[OSINTModule],
        *,
        semaphore: int = 5,
        verbose: bool = False,
    ) -> None:
        self.modules = list(modules)
        self.semaphore = asyncio.Semaphore(max(1, int(semaphore)))
        self.verbose = verbose

    def list_modules(self) -> List[OSINTModule]:
        return list(self.modules)

    def select_modules(
        self,
        *,
        target: str,
        target_type: str,
        module_names: Optional[Sequence[str]] = None,
    ) -> List[OSINTModule]:
        mods = [m for m in self.modules if target_type in getattr(m, "target_types", [])]
        if module_names:
            allow = {n.strip().lower() for n in module_names}
            mods = [m for m in mods if m.name.lower() in allow]
        return mods

    async def _run_module(self, module: OSINTModule, target: str, target_type: str) -> List[Finding]:
        if not module.validate(target):
            return []
        async with self.semaphore:
            try:
                return await module.execute(target, target_type)
            except Exception as e:  # pragma: no cover (defensive)
                if self.verbose:
                    return [
                        Finding(
                            source=module.name,
                            target=target,
                            target_type=target_type,
                            data={"error": f"{type(e).__name__}: {e}"},
                            confidence=0.0,
                        )
                    ]
                return []

    async def scan(
        self,
        target: str,
        *,
        target_type: Optional[str] = None,
        module_names: Optional[Sequence[str]] = None,
    ) -> List[Finding]:
        t = target.strip()
        t_type = (target_type or detect_target_type(t)).lower()
        modules = self.select_modules(target=t, target_type=t_type, module_names=module_names)
        tasks = [asyncio.create_task(self._run_module(m, t, t_type)) for m in modules]
        findings_nested = await asyncio.gather(*tasks) if tasks else []
        findings: List[Finding] = [f for group in findings_nested for f in group]
        return findings

    async def scan_many(
        self,
        targets: Iterable[str],
        *,
        target_type: Optional[str] = None,
        module_names: Optional[Sequence[str]] = None,
    ) -> List[Finding]:
        tasks = [
            asyncio.create_task(self.scan(t, target_type=target_type, module_names=module_names))
            for t in targets
            if t.strip()
        ]
        results = await asyncio.gather(*tasks) if tasks else []
        return [f for group in results for f in group]

    @staticmethod
    def export_json(findings: Sequence[Finding], path: Path) -> None:
        path = Path(path)
        payload = [f.to_dict() for f in findings]
        path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")

    @staticmethod
    def export_csv(findings: Sequence[Finding], path: Path) -> None:
        path = Path(path)
        with path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(
                f,
                fieldnames=["source", "target", "target_type", "confidence", "timestamp", "data"],
            )
            writer.writeheader()
            for finding in findings:
                writer.writerow(
                    {
                        "source": finding.source,
                        "target": finding.target,
                        "target_type": finding.target_type,
                        "confidence": f"{finding.confidence:.4f}",
                        "timestamp": finding.timestamp,
                        "data": json.dumps(finding.data, ensure_ascii=False),
                    }
                )
