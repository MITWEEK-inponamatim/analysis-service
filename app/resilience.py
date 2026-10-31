"""Retry with exponential backoff for external calls.

Only transient failures are retried: timeouts, connection problems, and the HTTP statuses
that mean "try again" (408/425/429/5xx). Validation errors and 4xx answers are returned to
the caller immediately, because retrying them cannot change the outcome (handoff 7.2).
"""

import asyncio
import logging
import os
from typing import Awaitable, Callable, TypeVar

import httpx

logger = logging.getLogger("threatlens.retry")

T = TypeVar("T")

RETRYABLE_STATUS = {408, 425, 429, 500, 502, 503, 504}


def attempts_default() -> int:
    try:
        configured = int(os.getenv("EXTERNAL_RETRY_ATTEMPTS", "3"))
    except ValueError:
        configured = 3
    return max(1, min(configured, 6))


def is_retryable(error: BaseException) -> bool:
    if isinstance(error, (httpx.ConnectError, httpx.ConnectTimeout, httpx.ReadTimeout, httpx.WriteTimeout, httpx.PoolTimeout, httpx.RemoteProtocolError, httpx.NetworkError)):
        return True
    if isinstance(error, (TimeoutError, ConnectionError)):
        return True
    if isinstance(error, httpx.HTTPStatusError):
        return error.response.status_code in RETRYABLE_STATUS
    return False


async def call_with_retry(
    operation: Callable[[], Awaitable[T]],
    *,
    name: str = "external",
    attempts: int | None = None,
    base_delay: float = 0.4,
    max_delay: float = 3.0,
) -> T:
    total = attempts or attempts_default()
    last_error: BaseException | None = None
    for attempt in range(1, total + 1):
        try:
            return await operation()
        except Exception as error:  # noqa: BLE001 - re-raised below when not retryable
            last_error = error
            if attempt >= total or not is_retryable(error):
                raise
            delay = min(max_delay, base_delay * (2 ** (attempt - 1)))
            logger.info("retrying %s after transient failure (attempt %d/%d)", name, attempt, total)
            try:
                from .metrics import metrics

                metrics.inc("external_retries", operation=name[:32])
            except Exception:
                pass
            await asyncio.sleep(delay)
    raise last_error if last_error else RuntimeError(f"{name} failed without an error")


async def json_request(client: httpx.AsyncClient, method: str, url: str, **kwargs) -> httpx.Response:
    """Send one request with retry, then raise for status so callers see 4xx immediately."""

    async def send() -> httpx.Response:
        response = await client.request(method, url, **kwargs)
        if response.status_code in RETRYABLE_STATUS:
            raise httpx.HTTPStatusError(f"retryable status {response.status_code}", request=response.request, response=response)
        return response

    response = await call_with_retry(send, name=f"{method} {url.split('?')[0][:120]}")
    response.raise_for_status()
    return response
