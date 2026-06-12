from __future__ import annotations

import asyncio
import socket
from typing import Dict, List, Optional

import aiohttp

from .base import Finding, OSINTModule
from .executor import detect_target_type


class IPGeolocationModule(OSINTModule):
    name = "ip-geolocation"
    description = "Geolocate IPs (country, city, ISP)"
    target_types = ["ip"]

    def validate(self, target: str) -> bool:
        return detect_target_type(target) == "ip"

    async def execute(self, target: str, target_type: str) -> List[Finding]:
        url = f"http://ip-api.com/json/{target}?fields=status,message,country,regionName,city,isp,org,as,query"
        timeout = aiohttp.ClientTimeout(total=10)
        headers = {"User-Agent": "osinter/1.0"}

        try:
            async with aiohttp.ClientSession(timeout=timeout, headers=headers) as session:
                async with session.get(url) as resp:
                    data = await resp.json(content_type=None)
        except Exception as e:
            return [self._err_finding(target=target, target_type=target_type, error=str(e))]

        if isinstance(data, dict) and data.get("status") == "success":
            payload = {
                "ip": data.get("query"),
                "country": data.get("country"),
                "region": data.get("regionName"),
                "city": data.get("city"),
                "isp": data.get("isp"),
                "org": data.get("org"),
                "as": data.get("as"),
            }
            return [
                Finding(
                    source=self.name,
                    target=target,
                    target_type=target_type,
                    data={k: v for k, v in payload.items() if v is not None},
                    confidence=0.95,
                )
            ]

        return [
            Finding(
                source=self.name,
                target=target,
                target_type=target_type,
                data={"error": data.get("message", "lookup failed")} if isinstance(data, dict) else {"error": "lookup failed"},
                confidence=0.0,
            )
        ]


class DNSModule(OSINTModule):
    name = "dns"
    description = "Resolve A and MX records"
    target_types = ["domain"]

    def validate(self, target: str) -> bool:
        return detect_target_type(target) == "domain"

    @staticmethod
    def _resolve_dns_dnspython(domain: str) -> Dict[str, List[str]]:
        import dns.resolver  # type: ignore

        out: Dict[str, List[str]] = {"a": [], "mx": []}

        try:
            answers = dns.resolver.resolve(domain, "A")
            out["a"] = sorted({a.to_text() for a in answers})
        except Exception:
            out["a"] = []

        try:
            answers = dns.resolver.resolve(domain, "MX")
            out["mx"] = sorted({str(r.exchange).rstrip(".") for r in answers})
        except Exception:
            out["mx"] = []

        return out

    @staticmethod
    def _resolve_dns_socket(domain: str) -> Dict[str, List[str]]:
        out: Dict[str, List[str]] = {"a": [], "mx": []}
        try:
            _, _, ips = socket.gethostbyname_ex(domain)
            out["a"] = sorted(set(ips))
        except Exception:
            out["a"] = []
        # MX is not available via the stdlib; leave empty.
        return out

    async def execute(self, target: str, target_type: str) -> List[Finding]:
        async def work() -> Dict[str, List[str]]:
            try:
                return await asyncio.to_thread(self._resolve_dns_dnspython, target)
            except Exception:
                return await asyncio.to_thread(self._resolve_dns_socket, target)

        result = await work()
        confidence = 0.99 if result.get("a") or result.get("mx") else 0.2
        return [
            Finding(
                source=self.name,
                target=target,
                target_type=target_type,
                data={"ips": result.get("a", []), "mx": result.get("mx", [])},
                confidence=confidence,
            )
        ]


class WHOISModule(OSINTModule):
    name = "whois"
    description = "Domain/IP registration info"
    target_types = ["domain", "ip"]

    def validate(self, target: str) -> bool:
        return detect_target_type(target) in {"domain", "ip"}

    @staticmethod
    def _whois_domain(domain: str) -> Dict[str, Optional[str]]:
        import whois  # type: ignore

        w = whois.whois(domain)
        # python-whois can return lists for some fields; normalize to strings.
        def _one(v):
            if v is None:
                return None
            if isinstance(v, (list, tuple)) and v:
                return str(v[0])
            return str(v)

        return {
            "domain_name": _one(getattr(w, "domain_name", None)),
            "registrar": _one(getattr(w, "registrar", None)),
            "creation_date": _one(getattr(w, "creation_date", None)),
            "expiration_date": _one(getattr(w, "expiration_date", None)),
            "name_servers": str(getattr(w, "name_servers", None)),
        }

    async def execute(self, target: str, target_type: str) -> List[Finding]:
        if target_type == "ip":
            return [
                Finding(
                    source=self.name,
                    target=target,
                    target_type=target_type,
                    data={"error": "IP WHOIS requires an additional provider (not enabled by default)."},
                    confidence=0.0,
                )
            ]

        try:
            data = await asyncio.to_thread(self._whois_domain, target)
        except Exception as e:
            return [self._err_finding(target=target, target_type=target_type, error=str(e))]

        cleaned = {k: v for k, v in data.items() if v not in (None, "None")}
        return [
            Finding(
                source=self.name,
                target=target,
                target_type=target_type,
                data=cleaned,
                confidence=0.90,
            )
        ]
