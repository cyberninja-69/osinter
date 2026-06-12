"""
osinter — Complete OSINT Framework

This package is intentionally small and focused:
- Simple Finding model
- Module interface (OSINTModule)
- Async executor (OSINTExecutor)
- Built-in modules (network + social)
"""

from .base import Finding, OSINTModule
from .executor import OSINTExecutor
from .modules_network import DNSModule, IPGeolocationModule, WHOISModule
from .modules_social import EmailFinderModule, HaveIBeenPwnedModule, SocialMediaModule

__all__ = [
    "Finding",
    "OSINTModule",
    "OSINTExecutor",
    "IPGeolocationModule",
    "DNSModule",
    "WHOISModule",
    "SocialMediaModule",
    "HaveIBeenPwnedModule",
    "EmailFinderModule",
]

__version__ = "1.0.0"
