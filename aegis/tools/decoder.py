from __future__ import annotations

import base64


def decode_base64(s: str) -> str:
    """
    Decode base64 string to UTF-8 text.
    Raises ValueError if decoding fails.
    """
    try:
        raw = base64.b64decode(s, validate=True)
        return raw.decode("utf-8", errors="replace")
    except Exception as e:
        raise ValueError(f"Invalid base64 payload: {e}") from e
