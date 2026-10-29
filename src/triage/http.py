"""The only module that talks to the network: timeouts, retries and backoff live here.

Ruff (TID251) rejects httpx/urllib.request/requests imports anywhere else in src/.
"""

import random
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from types import TracebackType
from typing import Self

import httpx

from triage import __version__

DEFAULT_TIMEOUT = httpx.Timeout(10.0, read=30.0)
RETRY_STATUSES = frozenset({429, 500, 502, 503, 504})
USER_AGENT = f"exposure-triage-agent/{__version__}"


class HttpError(Exception):
    """A request failed for good: a non-retryable status, or retries ran out."""

    def __init__(self, message: str, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


@dataclass(frozen=True)
class HttpResponse:
    """A successful response: final URL (with query string), status, and body text."""

    url: str
    status_code: int
    text: str


class HttpClient:
    """GET with explicit timeouts and retries on transport errors, 429 and 5xx.

    `transport`, `sleep` and `rng` are injectable so tests replay recorded fixtures through
    this exact code path without a network or real waiting.
    """

    def __init__(
        self,
        *,
        transport: httpx.BaseTransport | None = None,
        timeout: httpx.Timeout = DEFAULT_TIMEOUT,
        max_attempts: int = 4,
        backoff_base: float = 1.0,
        max_backoff: float = 30.0,
        sleep: Callable[[float], None] = time.sleep,
        rng: random.Random | None = None,
    ) -> None:
        if max_attempts < 1:
            raise ValueError("max_attempts must be at least 1")
        self.timeout = timeout
        self._max_attempts = max_attempts
        self._backoff_base = backoff_base
        self._max_backoff = max_backoff
        self._sleep = sleep
        self._rng = rng or random.Random()
        self._client = httpx.Client(
            transport=transport,
            timeout=timeout,
            follow_redirects=True,
            headers={"User-Agent": USER_AGENT},
        )

    def get(self, url: str, params: Mapping[str, str | int] | None = None) -> HttpResponse:
        failure = ""
        for attempt in range(self._max_attempts):
            retry_after: float | None = None
            try:
                resp = self._client.get(url, params=params)
            except httpx.TransportError as exc:
                failure = f"{type(exc).__name__}: {exc}"
            else:
                if resp.is_success:
                    return HttpResponse(str(resp.url), resp.status_code, resp.text)
                if resp.status_code not in RETRY_STATUSES:
                    raise HttpError(f"GET {url} returned {resp.status_code}", resp.status_code)
                failure = f"status {resp.status_code}"
                retry_after = _parse_retry_after(resp.headers.get("Retry-After"))
            if attempt + 1 < self._max_attempts:
                self._sleep(self._delay(attempt, retry_after))
        raise HttpError(f"GET {url} failed after {self._max_attempts} attempts ({failure})")

    def _delay(self, attempt: int, retry_after: float | None) -> float:
        if retry_after is not None:
            return min(retry_after, self._max_backoff)
        backoff = self._backoff_base * 2**attempt
        jitter = self._rng.uniform(0, 0.1 * backoff)
        return min(backoff + jitter, self._max_backoff)

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()


def _parse_retry_after(value: str | None) -> float | None:
    """Seconds from a Retry-After header; the HTTP-date form falls back to normal backoff."""
    if value is None:
        return None
    try:
        return max(0.0, float(value))
    except ValueError:
        return None
