from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any


_TOKEN_RE = re.compile(r"[a-zA-Z0-9']+")

# Synthetic threat signature keywords (demo-grade).
# These are used to generate an additional "signature match" signal.
_SIGNATURES: dict[str, list[str]] = {
    "phishing": ["click", "verify", "account", "login", "password", "bank", "urgent"],
    "scam": ["urgent", "prize", "won", "gift card", "wire transfer", "claim", "limited time"],
    "malware": ["download", "attached", "enable macros", "macro", "invoice", "malicious"],
}

_SUSPICIOUS_CATEGORIES = {"phishing", "scam", "malware"}


@dataclass(frozen=True)
class _SpamFingerprint:
    # Privacy-first: store token fingerprints, not raw user text.
    tokens: frozenset[str]
    category: str
    created_at: str


_SPAM_DB: list[_SpamFingerprint] = []
_MAX_MEMORY_ITEMS = 50


def reset_memory() -> None:
    _SPAM_DB.clear()


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _normalize(text: str) -> str:
    return (text or "").strip().lower()


def _tokenize(text: str) -> set[str]:
    t = _normalize(text)
    # Keep it simple: alphanumeric tokens only.
    return {m.group(0) for m in _TOKEN_RE.finditer(t)}


def signature_match(text: str) -> dict[str, Any]:
    """
    Returns a category guess + a signature score 0-100.
    """
    t = _normalize(text)
    if not t:
        return {"category": "unknown", "signature_score": 0, "found": []}

    best_cat = "unknown"
    best_hits = 0
    best_found: list[str] = []

    for cat, keywords in _SIGNATURES.items():
        hits: list[str] = []
        for kw in keywords:
            if kw in t:
                hits.append(kw)
        if len(hits) > best_hits:
            best_hits = len(hits)
            best_cat = cat
            best_found = hits

    # Scale based on total keywords per category (worst-case 0-100).
    denom = max(1, len(_SIGNATURES.get(best_cat, [])))
    signature_score = int(round((best_hits / denom) * 100))

    if best_hits == 0:
        return {"category": "unknown", "signature_score": 0, "found": []}
    return {"category": best_cat, "signature_score": signature_score, "found": best_found}


def store_observation(text: str, category: str, severity: str) -> None:
    """
    Stores a privacy-first token fingerprint only when the message is
    sufficiently suspicious, simulating "self-learning threat intelligence".
    """
    if not text:
        return

    cat = (category or "").lower().strip()
    sev = (severity or "").upper().strip()
    if cat not in _SUSPICIOUS_CATEGORIES:
        return
    if sev not in {"HIGH", "MEDIUM"}:
        return

    tokens = _tokenize(text)
    if not tokens:
        return

    _SPAM_DB.append(_SpamFingerprint(tokens=frozenset(tokens), category=cat, created_at=_now_iso()))
    if len(_SPAM_DB) > _MAX_MEMORY_ITEMS:
        # Drop oldest to keep memory bounded.
        del _SPAM_DB[: len(_SPAM_DB) - _MAX_MEMORY_ITEMS]


def pattern_match(text: str) -> dict[str, Any]:
    """
    Compares current tokens against previously stored fingerprints.
    Returns:
      - pattern_score: 0-100 (learned similarity)
      - match_category: category of the best matching prior fingerprint
      - match_count: how many stored fingerprints were compared (recent window)
    """
    if not _SPAM_DB:
        return {"pattern_score": 0, "match_category": "unknown", "match_count": 0}

    tokens = _tokenize(text)
    if not tokens:
        return {"pattern_score": 0, "match_category": "unknown", "match_count": 0}

    # Only compare with the recent window to keep it fast and "contextual".
    window = _SPAM_DB[-20:]
    best_ratio = 0.0
    best_cat = "unknown"

    for fp in window:
        # Jaccard similarity between token sets.
        union = len(tokens | set(fp.tokens)) or 1
        inter = len(tokens & set(fp.tokens))
        ratio = inter / union
        if ratio > best_ratio:
            best_ratio = ratio
            best_cat = fp.category

    pattern_score = int(round(best_ratio * 100))
    return {"pattern_score": pattern_score, "match_category": best_cat, "match_count": len(window)}


def combined_pattern_score(text: str) -> dict[str, Any]:
    """
    Combines:
      - learned similarity against previous spam fingerprints
      - deterministic signature match
    """
    learned = pattern_match(text)
    sig = signature_match(text)

    learned_score = int(learned.get("pattern_score", 0))
    signature_score = int(sig.get("signature_score", 0))

    # Weighted mix: learned evidence is slightly weaker early, signatures help stabilize.
    combined = int(round(learned_score * 0.65 + signature_score * 0.35))

    match_category = learned.get("match_category") or "unknown"
    # If signature is stronger than learned similarity, prefer the signature category.
    if signature_score >= learned_score and sig.get("category") != "unknown":
        match_category = sig.get("category")

    return {
        "pattern_score": combined,
        "match_category": match_category,
        "learned_pattern_score": learned_score,
        "signature_score": signature_score,
        "signature_found": sig.get("found") or [],
        "learned_window_count": learned.get("match_count", 0),
    }

