#!/usr/bin/env python3
# Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
"""Mapping evidence for docs/mappings/contextforge-6408-stale-authority.md.

Not a conformance family and not a lab vector. It executes two source files from an
IBM/mcp-context-forge checkout, unmodified and loaded in place, to answer one question
about their decision cache: does ttl_seconds bound the age of a decision served across
the in-memory and Redis tiers?

Usage:
    python3 two_tier_ttl.py <path to an IBM/mcp-context-forge checkout>

Requirements: git on PATH, pydantic 2. The script refuses to run unless the checkout
HEAD is the pinned commit and both loaded files match their pinned SHA-256.

Setup: a controlled monotonic clock replaces cache.time, a fake Redis honours setex
expiry on that same clock, and two DecisionCache instances stand in for two workers
that share the Redis. The only gateway symbol stubbed is the logging helper that
cache.py imports. Nothing here runs a ContextForge gateway or a real Redis.
"""
import asyncio
import hashlib
import importlib.util
import subprocess
import sys
import types
from pathlib import Path

PINNED_COMMIT = "380469fc2d50df599124b58c9ddea8ab2d739207"
PINNED_FILES = {
    "plugins/unified_pdp/cache.py": "ac968d1af1ff865105203d3a06e1a1cb0b11ed92f86cfcb9a53c835f2ededb6f",
    "plugins/unified_pdp/pdp_models.py": "7e636e7b862a7620ae814143b1389705d5dbd8f531adb0e85133df5514282cf5",
}
TTL_SECONDS = 60
PKG = "unified_pdp_under_test"


def refuse(message):
    print(f"REFUSED: {message}")
    sys.exit(2)


if len(sys.argv) != 2:
    refuse("pass the path to an IBM/mcp-context-forge checkout as the only argument")
root = Path(sys.argv[1]).resolve()

try:
    head = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "HEAD"], capture_output=True, text=True, check=True
    ).stdout.strip()
except (OSError, subprocess.CalledProcessError):
    refuse(f"{root} is not a git checkout")
if head != PINNED_COMMIT:
    refuse(f"checkout HEAD is {head}, expected {PINNED_COMMIT}")

for rel, expected in PINNED_FILES.items():
    path = root / rel
    if not path.is_file():
        refuse(f"{rel} not found in the checkout")
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    if actual != expected:
        refuse(f"{rel} sha256 is {actual}, expected {expected}")
print(f"pinned: commit {PINNED_COMMIT}, both files match their SHA-256")

# Load pdp_models and cache as a synthetic package so plugins/unified_pdp/__init__.py,
# which imports the whole plugin, is not executed. The two files load as they are.
pkg = types.ModuleType(PKG)
pkg.__path__ = [str(root / "plugins" / "unified_pdp")]
sys.modules[PKG] = pkg
for name in ("mcpgateway", "mcpgateway.utils"):
    sys.modules.setdefault(name, types.ModuleType(name))
url_auth = types.ModuleType("mcpgateway.utils.url_auth")
url_auth.sanitize_url_for_logging = lambda url: url
sys.modules["mcpgateway.utils.url_auth"] = url_auth


def load(mod):
    spec = importlib.util.spec_from_file_location(f"{PKG}.{mod}", root / "plugins" / "unified_pdp" / f"{mod}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[f"{PKG}.{mod}"] = module
    spec.loader.exec_module(module)
    return module


models = load("pdp_models")
cache_mod = load("cache")


class Clock:
    def __init__(self):
        self.t = 1000.0

    def monotonic(self):
        return self.t


clock = Clock()
cache_mod.time = types.SimpleNamespace(monotonic=clock.monotonic)


class FakeRedis:
    """setex and get, with expiry measured on the same controlled clock."""

    def __init__(self):
        self.store = {}

    async def setex(self, key, ttl, value):
        self.store[key] = (value, clock.t + ttl)

    async def get(self, key):
        item = self.store.get(key)
        if item is None:
            return None
        value, expires_at = item
        if clock.t >= expires_at:
            del self.store[key]
            return None
        return value


redis = FakeRedis()


def worker():
    cache = cache_mod.DecisionCache(models.CacheConfig(enabled=True, ttl_seconds=TTL_SECONDS, max_entries=100))

    async def get_redis():
        return redis

    cache._get_redis = get_redis
    return cache


failures = 0


def check(label, ok):
    global failures
    print(("PASS " if ok else "FAIL ") + label)
    if not ok:
        failures += 1


async def main():
    subject = models.Subject(email="alice@example.com", roles=["developer"])
    resource = models.Resource(type="tool", id="db-query")
    context = models.Context(ip="10.0.0.1", session_id="s1")
    action = "tools.invoke"
    allow = models.AccessDecision(decision=models.Decision.ALLOW, reason="test allow")
    key = cache_mod._build_cache_key(subject, action, resource, context)

    a, b = worker(), worker()
    t0 = clock.t

    async def read(cache):
        return await cache.get(subject, action, resource, context)

    # t+0: worker A caches an allow. Memory and Redis each get the 60 s lifetime.
    await a.put(subject, action, resource, context, allow)
    check("t+0 worker A serves the decision from memory", (await read(a)) is not None)

    # t+59: worker B misses memory and reads Redis, which has 1 s of lifetime left.
    clock.t = t0 + 59
    served = await read(b)
    check("t+59 worker B serves the decision from Redis", served is not None and served.decision == models.Decision.ALLOW)

    # t+61: the decision is 61 s old and the Redis entry has expired.
    clock.t = t0 + 61
    check("t+61 the Redis entry has expired", (await redis.get(f"pdp:decision:{key}")) is None)
    check("t+61 worker A, memory tier only, no longer serves it", (await read(a)) is None)
    check("t+61 worker B still serves it", (await read(b)) is not None)

    # t+118.5: worker B's refilled memory entry runs until t+119.
    clock.t = t0 + 118.5
    check("t+118.5 worker B still serves it", (await read(b)) is not None)

    # t+119.5: past the refilled lifetime.
    clock.t = t0 + 119.5
    check("t+119.5 worker B no longer serves it", (await read(b)) is None)

    print()
    if failures:
        print(f"{failures} check(s) failed")
        sys.exit(1)
    print(
        f"RESULT: with ttl_seconds={TTL_SECONDS}, a decision written at t+0 was still served at t+118.5, "
        "because a Redis hit at t+59 started a fresh in-memory TTL in the reading worker."
    )


asyncio.run(main())
