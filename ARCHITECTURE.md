# ARCHITECTURE — osinter

## Overview

`osinter` is a small, extensible OSINT framework built around:

- A simple `Finding` model (normalized output)
- A small `OSINTModule` ABC (input validation + async execution)
- An `OSINTExecutor` orchestrator that:
  - detects target type automatically
  - selects compatible modules
  - runs modules concurrently with a semaphore (rate limiting)
  - aggregates findings and optionally exports JSON/CSV
- A CLI (`osinter scan`, `osinter modules`) and Rich output formatting

## Target detection

The executor classifies a target into one of:

- `ip` via `ipaddress.ip_address`
- `email` via a conservative regex
- `domain` via a simple domain pattern and label checks
- otherwise `username`

You can override with `-t/--type` in the CLI.

## Concurrency model

Each module runs as an async task, but some modules wrap blocking libraries using
`asyncio.to_thread()` to keep the event loop responsive.

Global rate limiting is done with a semaphore:

- `--threads N` maps to `semaphore=N`
- Each module execution acquires one slot

This keeps scans fast while reducing the chance of accidental over-requesting.

## Adding modules

Create a new module by subclassing `OSINTModule`:

```python
from osinter.base import OSINTModule, Finding

class MyModule(OSINTModule):
    name = "my-module"
    description = "Does something cool"
    target_types = ["username"]

    async def execute(self, target: str) -> list[Finding]:
        return [Finding(
            source=self.name,
            target=target,
            target_type="username",
            data={"hello": "world"},
            confidence=0.9,
        )]
```

Then register it in `osinter/cli.py` by adding it to `DEFAULT_MODULES`.

## Output model

`Finding.data` is a dict so each module can return structured results. The CLI
groups findings by `source` and uses Rich tables for a clean terminal report.

## Error handling philosophy

Modules are expected to fail sometimes (network issues, rate limiting, missing
API keys). A module should never crash the scan: it should return either:

- an empty list (no findings), or
- a `Finding` with `data={"error": "...", ...}` and low confidence
