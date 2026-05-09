"""Utilities for redacting sensitive data from log output.

Centralizes the rule "what's safe to log" so request logs can be forwarded to
shared logging pipelines without leaking Authorization, Cookie, API keys, etc.
"""

from collections.abc import Iterable, Mapping


REDACTED = "[REDACTED]"

# Header names that are safe to log in plaintext. Matched case-insensitively.
# Anything outside this set has its value replaced by REDACTED.
DEFAULT_HEADER_ALLOWLIST: frozenset[str] = frozenset(
    {
        "x-request-id",
        "x-trace-id",
        "g-trace-id",
        "trace-id",
        "x-env",
        "user-agent",
        "content-type",
        "accept",
    }
)


def redact_headers(
    headers: Mapping[str, str],
    allowlist: Iterable[str] | None = None,
) -> dict[str, str]:
    """Return a plain dict of headers with non-allowlisted values replaced by REDACTED.

    Args:
        headers: Any Mapping of header name -> value (Starlette ``Headers``,
            plain dict, etc.).
        allowlist: Header names safe to log in plaintext. Defaults to
            ``DEFAULT_HEADER_ALLOWLIST``. Names are normalized to lowercase
            before comparison so callers don't need to pre-normalize.
    """
    safe = (
        DEFAULT_HEADER_ALLOWLIST
        if allowlist is None
        else frozenset(name.lower() for name in allowlist)
    )
    return {key: (value if key.lower() in safe else REDACTED) for key, value in headers.items()}
