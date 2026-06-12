from __future__ import annotations

import abc
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(slots=True)
class Finding:
    """
    Normalized output from a single module.

    Fields match the README contract exactly.
    """

    source: str
    target: str
    target_type: str  # "ip" | "domain" | "email" | "username"
    data: Dict[str, Any]
    confidence: float = 0.0  # 0.0 - 1.0
    timestamp: str = field(default_factory=utc_now_iso)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source,
            "target": self.target,
            "target_type": self.target_type,
            "data": self.data,
            "confidence": float(self.confidence),
            "timestamp": self.timestamp,
        }


class OSINTModule(abc.ABC):
    """
    Base interface for all OSINT modules.

    Subclasses must:
    - set name/description/target_types
    - implement validate() and async execute()
    """

    name: str = "module"
    description: str = "Base OSINT module"
    target_types: List[str] = []

    @abc.abstractmethod
    def validate(self, target: str) -> bool:
        raise NotImplementedError

    @abc.abstractmethod
    async def execute(self, target: str, target_type: str) -> List[Finding]:
        raise NotImplementedError

    def _err_finding(self, *, target: str, target_type: str, error: str) -> Finding:
        return Finding(
            source=self.name,
            target=target,
            target_type=target_type,
            data={"error": error},
            confidence=0.0,
        )
