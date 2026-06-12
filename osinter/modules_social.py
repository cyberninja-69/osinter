from __future__ import annotations

import os
from typing import Dict, List

import aiohttp

from .base import Finding, OSINTModule
from .executor import detect_target_type


class SocialMediaModule(OSINTModule):
    name = "social-media"
    description = "Check 7 social platforms"
    target_types = ["username"]

    PLATFORMS: Dict[str, str] = {
        "github": "https://github.com/{u}",
        "twitter": "https://twitter.com/{u}",
        "instagram": "https://www.instagram.com/{u}/",
        "reddit": "https://www.reddit.com/user/{u}/",
        "tiktok": "https://www.tiktok.com/@{u}",
        "medium": "https://medium.com/@{u}",
        "devto": "https://dev.to/{u}",
    }

    def validate(self, target: str) -> bool:
        return detect_target_type(target) == "username" and len(target.strip()) >= 2

    async def execute(self, target: str, target_type: str) -> List[Finding]:
        timeout = aiohttp.ClientTimeout(total=10)
        headers = {"User-Agent": "osinter/1.0"}

        results: Dict[str, Dict[str, str | int | bool]] = {}

        async with aiohttp.ClientSession(timeout=timeout, headers=headers) as session:
            for platform, template in self.PLATFORMS.items():
                url = template.format(u=target)
                try:
                    async with session.get(url, allow_redirects=True) as resp:
                        status = resp.status
                    exists = status in (200, 301, 302, 303, 307, 308)
                    results[platform] = {"url": url, "status": status, "exists": exists}
                except Exception as e:
                    results[platform] = {"url": url, "status": -1, "exists": False, "error": str(e)}

        found_any = any(v.get("exists") is True for v in results.values())
        confidence = 0.85 if found_any else 0.40

        return [
            Finding(
                source=self.name,
                target=target,
                target_type=target_type,
                data={"profiles": results},
                confidence=confidence,
            )
        ]


class HaveIBeenPwnedModule(OSINTModule):
    name = "haveibeenpwned"
    description = "Check email breaches"
    target_types = ["email"]

    def validate(self, target: str) -> bool:
        return detect_target_type(target) == "email"

    async def execute(self, target: str, target_type: str) -> List[Finding]:
        api_key = os.getenv("HIBP_API_KEY", "").strip()
        if not api_key:
            return [
                Finding(
                    source=self.name,
                    target=target,
                    target_type=target_type,
                    data={"error": "Missing HIBP_API_KEY. Set it in .env (see .env.example)."},
                    confidence=0.0,
                )
            ]

        url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{target}"
        timeout = aiohttp.ClientTimeout(total=10)
        headers = {
            "hibp-api-key": api_key,
            "user-agent": "osinter/1.0",
            "accept": "application/json",
        }

        async with aiohttp.ClientSession(timeout=timeout, headers=headers) as session:
            try:
                async with session.get(url, params={"truncateResponse": "true"}) as resp:
                    if resp.status == 404:
                        return [
                            Finding(
                                source=self.name,
                                target=target,
                                target_type=target_type,
                                data={"breaches": [], "pwned": False},
                                confidence=0.95,
                            )
                        ]
                    if resp.status in (401, 403):
                        return [
                            Finding(
                                source=self.name,
                                target=target,
                                target_type=target_type,
                                data={"error": f"Unauthorized ({resp.status}). Check HIBP_API_KEY."},
                                confidence=0.0,
                            )
                        ]
                    if resp.status != 200:
                        text = await resp.text()
                        return [
                            Finding(
                                source=self.name,
                                target=target,
                                target_type=target_type,
                                data={"error": f"HTTP {resp.status}: {text[:200]}"},
                                confidence=0.0,
                            )
                        ]

                    data = await resp.json(content_type=None)
            except Exception as e:
                return [self._err_finding(target=target, target_type=target_type, error=str(e))]

        breaches = []
        if isinstance(data, list):
            breaches = [b.get("Name") for b in data if isinstance(b, dict) and b.get("Name")]

        return [
            Finding(
                source=self.name,
                target=target,
                target_type=target_type,
                data={"breaches": breaches, "pwned": bool(breaches)},
                confidence=0.95,
            )
        ]


class EmailFinderModule(OSINTModule):
    name = "email-finder"
    description = "Generate common email patterns"
    target_types = ["domain"]

    def validate(self, target: str) -> bool:
        return detect_target_type(target) == "domain"

    async def execute(self, target: str, target_type: str) -> List[Finding]:
        domain = target.strip().lower()
        patterns = [
            "{first}.{last}@" + domain,
            "{first}{last}@" + domain,
            "{f}{last}@" + domain,
            "{first}{l}@" + domain,
            "{first}@" + domain,
            "{last}@" + domain,
        ]
        return [
            Finding(
                source=self.name,
                target=target,
                target_type=target_type,
                data={
                    "patterns": patterns,
                    "note": "Replace placeholders like {first}/{last} with real names.",
                },
                confidence=0.60,
            )
        ]
