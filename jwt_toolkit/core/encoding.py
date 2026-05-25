import base64

# base64url encode/decode helpers — JWT strips '=' padding by spec, so every
# encode trims it and every decode restores it.


def _pad(value: str) -> str:
    return value + "=" * (-len(value) % 4)


def base64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def base64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(_pad(value))


def base64_decode_padded(value: str) -> bytes:
    # Standard base64 (not url-safe) with the same padding restoration —
    # used by `crack` when interpreting a wordlist entry as a base64 secret.
    return base64.b64decode(_pad(value))
