from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any


@dataclass(frozen=True)
class SafeCircleStatusMeta:
    created_at: str
    location: str
    severity: str


_HISTORY: list[dict[str, Any]] = []
_MAX_HISTORY = 40


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def reset_history() -> None:
    _HISTORY.clear()


def _derive_key_bytes(passphrase: str, *, length: int) -> bytes:
    # Demo-grade "encryption": deterministic XOR stream derived from passphrase.
    # This is for conceptual simulation only (not for real security).
    p = (passphrase or "").encode("utf-8")
    digest = hashlib.sha256(p).digest()
    # Repeat hash bytes to reach target length.
    return (digest * (length // len(digest) + 1))[:length]


def _xor_bytes(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i] for i, b in enumerate(data))


def encrypt_status(status_text: str, *, passphrase: str, location: str, severity: str) -> str:
    payload = {
        "status_text": status_text,
        "location": location,
        "severity": severity,
        "created_at": _now_iso(),
        "v": 1,
    }
    plaintext = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    key = _derive_key_bytes(passphrase, length=len(plaintext))
    cipher = _xor_bytes(plaintext, key)
    return base64.urlsafe_b64encode(cipher).decode("ascii")


def decrypt_status(share_code: str, *, passphrase: str) -> dict[str, Any]:
    if not share_code:
        raise ValueError("share_code is required")
    if not passphrase:
        raise ValueError("passphrase is required")

    try:
        cipher = base64.urlsafe_b64decode(share_code.encode("ascii"))
    except Exception as e:
        raise ValueError("share_code is not valid base64") from e

    key = _derive_key_bytes(passphrase, length=len(cipher))
    plaintext = _xor_bytes(cipher, key)
    try:
        payload = json.loads(plaintext.decode("utf-8"))
    except Exception as e:
        # Wrong passphrase typically results in invalid JSON.
        raise ValueError("passphrase is incorrect for this share code") from e

    if payload.get("v") != 1:
        raise ValueError("unsupported share code version")
    return payload


def store_shared_status(*, share_code: str, location: str, severity: str) -> None:
    _HISTORY.append(
        {
            "created_at": _now_iso(),
            "location": location,
            "severity": severity,
            "share_code_preview": share_code[:12] + "...",
        }
    )
    if len(_HISTORY) > _MAX_HISTORY:
        del _HISTORY[: len(_HISTORY) - _MAX_HISTORY]


def get_history(limit: int = 5) -> list[SafeCircleStatusMeta]:
    limit = max(1, min(50, int(limit)))
    items = _HISTORY[-limit:][::-1]
    return [SafeCircleStatusMeta(created_at=i["created_at"], location=i["location"], severity=i["severity"]) for i in items]

