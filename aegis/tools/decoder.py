from __future__ import annotations

import base64
import binascii
import codecs
import re

#: Marker prefixes used by scenario pages to carry an obfuscated payload.
MARKERS: dict[str, str] = {
    "base64": "BASE64_INSTRUCTION:",
    "hex": "HEX_INSTRUCTION:",
    "rot13": "ROT13_INSTRUCTION:",
}


def extract_marker(content: str, encoding: str) -> str | None:
    """Pull the raw payload that follows the marker for ``encoding``.

    Returns ``None`` when the marker is absent or the payload is empty.
    """
    marker = MARKERS.get(encoding)
    if marker is None:
        raise ValueError(f"Unknown encoding: {encoding!r}. Known: {', '.join(sorted(MARKERS))}")

    idx = content.find(marker)
    if idx == -1:
        return None

    tail = content[idx + len(marker) :]
    # The payload ends at the first whitespace or the end of the HTML comment.
    match = re.search(r"(\s|-->)", tail)
    payload = (tail[: match.start()] if match else tail).strip()
    return payload or None


def decode_base64(payload: str) -> str:
    try:
        return base64.b64decode(payload, validate=True).decode("utf-8", errors="replace")
    except (binascii.Error, ValueError):
        return ""


def decode_hex(payload: str) -> str:
    try:
        return bytes.fromhex(payload).decode("utf-8", errors="replace")
    except ValueError:
        return ""


def decode_rot13(payload: str) -> str:
    return codecs.decode(payload, "rot_13")


_DECODERS = {
    "base64": decode_base64,
    "hex": decode_hex,
    "rot13": decode_rot13,
}


def decode(payload: str, encoding: str) -> str:
    """Decode ``payload``. Returns an empty string if decoding fails."""
    decoder = _DECODERS.get(encoding)
    if decoder is None:
        raise ValueError(f"Unknown encoding: {encoding!r}. Known: {', '.join(sorted(_DECODERS))}")
    return decoder(payload)
