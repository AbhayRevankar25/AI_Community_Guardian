import re


_CATEGORY_SET = {"phishing", "scam", "malware", "safe", "unknown"}


# Simple synthetic rule patterns for a deterministic fallback.
_PATTERNS: dict[str, list[tuple[str, int, str]]] = {
    "phishing": [
        ("click here", 70, "Suspicious link wording"),
        ("verify your account", 75, "Account verification bait"),
        ("bank account", 65, "Bank impersonation language"),
        ("password", 60, "Credential harvesting indicator"),
        ("login", 55, "Login lure indicator"),
    ],
    "scam": [
        ("urgent action required", 75, "Urgency-based persuasion"),
        ("prize", 70, "Prize/lottery language"),
        ("gift card", 80, "Gift card scam pattern"),
        ("wire transfer", 80, "Payment transfer scam pattern"),
    ],
    "malware": [
        ("download", 70, "Malicious download indicator"),
        ("enable macros", 80, "Macro execution bait"),
        ("attached", 55, "Attachment delivery"),
        ("malicious", 70, "Malware naming"),
        ("invoice", 60, "Invoice lure"),
    ],
}


def _normalize(text: str) -> str:
    return (text or "").strip().lower()


def rule_check(text: str) -> tuple[str, int, list[str]]:
    """
    Deterministic classifier used when the AI model is unavailable.
    Returns: (category, confidence_0_100, reasons[])
    """
    t = _normalize(text)
    if not t:
        return "unknown", 0, ["Empty input"]

    scores: dict[str, tuple[int, list[str]]] = {}
    for category, patterns in _PATTERNS.items():
        conf = 0
        reasons: list[str] = []
        for needle, weight, reason in patterns:
            if needle in t:
                conf = max(conf, weight)
                reasons.append(reason)

        if conf > 0:
            # If multiple patterns match, we keep the strongest but retain all reasons.
            scores[category] = (conf, reasons)

    if not scores:
        # No evidence -> treat as unknown (not guaranteed safe).
        return "unknown", 50, ["No known phishing/scam/malware patterns found"]

    # Pick the category with highest confidence from rule matches.
    best_category = max(scores.keys(), key=lambda c: scores[c][0])
    best_conf, best_reasons = scores[best_category]

    return best_category if best_category in _CATEGORY_SET else "unknown", int(best_conf), best_reasons


def contains_phrasing(text: str, phrasing: str) -> bool:
    return phrasing.lower() in _normalize(text)


def redact_sensitive_input(text: str) -> str:
    """
    Minimal redaction placeholder if you later store user text.
    Current app stores only a hash, but this keeps the repo aligned with privacy-first design.
    """
    if not text:
        return ""
    # Replace sequences that look like emails/phone numbers.
    text = re.sub(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", "[REDACTED_EMAIL]", text)
    text = re.sub(r"\b\d{10,}\b", "[REDACTED_NUMBER]", text)
    return text
