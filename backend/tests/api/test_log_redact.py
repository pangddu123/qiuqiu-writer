from starlette.datastructures import Headers

from memos.api.utils.log_redact import (
    DEFAULT_HEADER_ALLOWLIST,
    REDACTED,
    redact_headers,
)


def test_allowlisted_values_pass_through():
    out = redact_headers({"user-agent": "Mozilla", "x-trace-id": "abc-123"})
    assert out == {"user-agent": "Mozilla", "x-trace-id": "abc-123"}


def test_non_allowlisted_values_are_redacted():
    out = redact_headers(
        {
            "authorization": "Bearer secret-token",
            "cookie": "session=xyz",
            "x-anthropic-api-key": "sk-ant-...",
        }
    )
    assert out == {
        "authorization": REDACTED,
        "cookie": REDACTED,
        "x-anthropic-api-key": REDACTED,
    }


def test_allowlist_match_is_case_insensitive():
    out = redact_headers({"User-Agent": "Mozilla", "AUTHORIZATION": "Bearer x"})
    assert out == {"User-Agent": "Mozilla", "AUTHORIZATION": REDACTED}


def test_empty_headers_returns_empty_dict():
    assert redact_headers({}) == {}


def test_starlette_headers_input_is_supported():
    raw = Headers({"authorization": "Bearer x", "user-agent": "Mozilla"})
    out = redact_headers(raw)
    assert out["authorization"] == REDACTED
    assert out["user-agent"] == "Mozilla"


def test_custom_allowlist_overrides_default():
    out = redact_headers(
        {"user-agent": "Mozilla", "x-custom-trace": "trace-1", "cookie": "s=1"},
        allowlist={"x-custom-trace"},
    )
    assert out == {
        "user-agent": REDACTED,
        "x-custom-trace": "trace-1",
        "cookie": REDACTED,
    }


def test_custom_allowlist_normalizes_case():
    out = redact_headers({"user-agent": "Mozilla"}, allowlist={"USER-AGENT"})
    assert out == {"user-agent": "Mozilla"}


def test_default_allowlist_is_lowercase_only():
    # Sanity: defaults must be pre-lowercased so case-insensitive comparison is correct.
    assert all(name == name.lower() for name in DEFAULT_HEADER_ALLOWLIST)
