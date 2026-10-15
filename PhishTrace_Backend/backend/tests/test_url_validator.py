import pytest

from backend.services.url_validator import validate_and_normalize_url


@pytest.mark.parametrize(("value", "expected"), [
    ("example.com", "https://example.com"),
    ("example.com/login", "https://example.com/login"),
    ("https://Example.com/Case", "https://Example.com/Case"),
    ("http://example.com:8080/path?q=1", "http://example.com:8080/path?q=1"),
    ("//example.com/a", "https://example.com/a"),
    ("localhost:5055/health", "https://localhost:5055/health"),
    ("https://example.com/#section", "https://example.com/#section"),
])
def test_valid_urls_are_normalized(value, expected):
    assert validate_and_normalize_url(value) == expected


@pytest.mark.parametrize("value", [
    None,
    123,
    "",
    "   ",
    "javascript:alert(1)",
    "file:///etc/passwd",
    "https://",
    "https://example.com:99999/",
    "https://user:password@example.com/",
    "https://bad host.example/",
    "https://-invalid.example/",
    "https://example..com/",
    "https://example.com\\@evil.example/",
])
def test_invalid_urls_are_rejected(value):
    with pytest.raises(ValueError):
        validate_and_normalize_url(value)


def test_url_length_is_limited():
    with pytest.raises(ValueError, match="characters or fewer"):
        validate_and_normalize_url("a" * 50, max_length=20)
