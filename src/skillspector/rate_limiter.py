"""Adaptive rate limiter for Vertex AI LLM calls.

For small scans (<= ADAPTIVE_THRESHOLD files) the limiter uses aggressive
concurrency (10 per analyzer, no global gate) matching upstream behavior.
For large scans the limiter enforces a process-wide concurrency cap with
exponential backoff + jitter on 429 (RateLimitError) as a second-chance
retry layer above LangChain's built-in tenacity retry.

Call ``configure(file_count)`` once at scan start (before any LLM calls)
to set the mode.  If never called, defaults to throttled mode for safety.

Uses ``threading.Semaphore`` (not ``asyncio.Semaphore``) because LangGraph
runs analyzer nodes in separate threads, each with its own event loop.
The async path uses non-blocking ``acquire(blocking=False)`` with
``asyncio.sleep`` polling to avoid exhausting the default thread-pool
executor when hundreds of coroutines contend for the semaphore.
"""

from __future__ import annotations

import asyncio
import logging
import os
import random
import threading
import time

logger = logging.getLogger(__name__)

ADAPTIVE_THRESHOLD = 50
_AGGRESSIVE_CONCURRENCY = 10
_THROTTLED_CONCURRENCY = 5
_ENV_CONCURRENCY_KEY = "SKILLSPECTOR_MAX_LLM_CONCURRENCY"

_BACKOFF_BASE = 4.0
_BACKOFF_MAX = 120.0
_MAX_RETRIES = 6

_SEM_POLL_INTERVAL = 0.05

_throttled = True
_concurrency: int = _THROTTLED_CONCURRENCY
_semaphore = threading.Semaphore(_THROTTLED_CONCURRENCY)


def configure(file_count: int) -> None:
    """Set limiter mode based on scan size.  Must be called before LLM calls.

    If ``SKILLSPECTOR_MAX_LLM_CONCURRENCY`` is set, that value overrides the
    adaptive logic entirely (user-specified concurrency wins).
    """
    global _throttled, _concurrency, _semaphore

    env_override = os.environ.get(_ENV_CONCURRENCY_KEY, "").strip()
    if env_override:
        try:
            explicit = max(1, int(env_override))
            _throttled = True
            _concurrency = explicit
            _semaphore = threading.Semaphore(explicit)
            logger.info(
                "Rate limiter: env override %s=%d (file_count=%d ignored)",
                _ENV_CONCURRENCY_KEY, explicit, file_count,
            )
            return
        except ValueError:
            logger.warning(
                "Invalid %s=%r; falling back to adaptive logic",
                _ENV_CONCURRENCY_KEY, env_override,
            )

    if file_count <= ADAPTIVE_THRESHOLD:
        _throttled = False
        _concurrency = _AGGRESSIVE_CONCURRENCY
        logger.info(
            "Rate limiter: aggressive mode (%d files <= %d threshold, concurrency=%d)",
            file_count, ADAPTIVE_THRESHOLD, _concurrency,
        )
    else:
        _throttled = True
        _concurrency = _THROTTLED_CONCURRENCY
        logger.info(
            "Rate limiter: throttled mode (%d files > %d threshold, concurrency=%d)",
            file_count, ADAPTIVE_THRESHOLD, _concurrency,
        )

    _semaphore = threading.Semaphore(_concurrency)


def _is_rate_limit_error(exc: BaseException) -> bool:
    """Check whether *exc* is a 429 / rate-limit error from any layer."""
    cls_name = type(exc).__name__
    if "RateLimitError" in cls_name:
        return True
    if hasattr(exc, "status_code") and getattr(exc, "status_code", None) == 429:
        return True
    msg = str(exc)
    return "429" in msg and ("rate" in msg.lower() or "quota" in msg.lower())


async def _acquire_async() -> None:
    """Acquire the threading semaphore without blocking the event loop.

    Uses non-blocking try-acquire with asyncio.sleep polling instead of
    run_in_executor, which would deadlock when hundreds of coroutines
    exhaust the default thread pool all waiting to acquire.
    """
    while not _semaphore.acquire(blocking=False):
        await asyncio.sleep(_SEM_POLL_INTERVAL)


def _release() -> None:
    _semaphore.release()


async def rate_limited_ainvoke(llm: object, prompt: str) -> object:
    """Async invoke with concurrency gate + backoff (throttled) or plain gate (aggressive)."""
    if not _throttled:
        await _acquire_async()
        try:
            return await llm.ainvoke(prompt)  # type: ignore[union-attr]
        finally:
            _release()

    last_exc: BaseException | None = None
    for attempt in range(_MAX_RETRIES + 1):
        await _acquire_async()
        try:
            return await llm.ainvoke(prompt)  # type: ignore[union-attr]
        except Exception as exc:
            if not _is_rate_limit_error(exc):
                raise
            last_exc = exc
        finally:
            _release()

        delay = min(_BACKOFF_BASE * (2 ** attempt), _BACKOFF_MAX)
        jitter = random.uniform(0, delay * 0.5)
        total = delay + jitter
        logger.warning(
            "Rate limited (attempt %d/%d), backing off %.1fs before retry",
            attempt + 1,
            _MAX_RETRIES + 1,
            total,
        )
        await asyncio.sleep(total)

    raise last_exc  # type: ignore[misc]


def rate_limited_invoke(llm: object, prompt: str) -> object:
    """Sync invoke with concurrency gate + backoff (throttled) or plain gate (aggressive)."""
    if not _throttled:
        _semaphore.acquire()
        try:
            return llm.invoke(prompt)  # type: ignore[union-attr]
        finally:
            _release()

    last_exc: BaseException | None = None
    for attempt in range(_MAX_RETRIES + 1):
        _semaphore.acquire()
        try:
            return llm.invoke(prompt)  # type: ignore[union-attr]
        except Exception as exc:
            if not _is_rate_limit_error(exc):
                raise
            last_exc = exc
        finally:
            _release()

        delay = min(_BACKOFF_BASE * (2 ** attempt), _BACKOFF_MAX)
        jitter = random.uniform(0, delay * 0.5)
        total = delay + jitter
        logger.warning(
            "Rate limited (attempt %d/%d), backing off %.1fs before retry",
            attempt + 1,
            _MAX_RETRIES + 1,
            total,
        )
        time.sleep(total)

    raise last_exc  # type: ignore[misc]
