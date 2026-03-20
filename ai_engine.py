import json
import os
import re
from typing import Any

import requests
from dotenv import load_dotenv


# Load environment variables from `.env` (if present) so users can
# just copy `.env.example` and set `GEMINI_API_KEY`.
load_dotenv()


_VALID_CATEGORIES = {"phishing", "scam", "malware", "safe", "unknown"}


class GeminiConfigError(RuntimeError):
    pass


def _parse_gemini_json(text_out: str) -> dict[str, Any]:
    """
    Gemini may wrap JSON in extra text. We extract the first JSON object we can find.
    """
    if not text_out:
        raise ValueError("Empty Gemini response")

    # Try direct JSON first
    try:
        parsed = json.loads(text_out)
        if isinstance(parsed, dict):
            return parsed
    except Exception:
        pass

    # Extract { ... } blob
    start = text_out.find("{")
    end = text_out.rfind("}")
    if start == -1 or end == -1 or end <= start:
        raise ValueError("Could not locate JSON in Gemini response")

    blob = text_out[start : end + 1]
    parsed = json.loads(blob)
    if not isinstance(parsed, dict):
        raise ValueError("Parsed Gemini JSON is not an object")
    return parsed


def analyze_with_gemini(text: str) -> dict[str, Any]:
    api_key = os.getenv("GEMINI_API_KEY", "").strip()
    if not api_key:
        raise GeminiConfigError("GEMINI_API_KEY is not set")

    model = os.getenv("GEMINI_MODEL", "gemini-1.5-flash").strip()
    if not model:
        raise GeminiConfigError("GEMINI_MODEL is empty")

    endpoint = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
    prompt = (
        "You are a cybersecurity email classifier. Classify the message into exactly one category:\n"
        "- phishing\n"
        "- scam\n"
        "- malware\n"
        "- safe\n"
        "- unknown\n\n"
        "Return STRICT JSON only (no markdown, no extra text) with exactly these keys:\n"
        "- category: string\n"
        "- summary: string (exactly 1 sentence)\n"
        "- confidence: integer 0-100\n"
        "- reason: string (short; mention the key indicators that triggered the decision)\n\n"
        "Critical scam handling (advance-fee / lottery / winner):\n"
        "If the message includes MOST of the following indicators, it MUST be classified as 'scam' with HIGH confidence:\n"
        "1) Mentions being a 'winner', 'lucky winner', 'prize', 'lottery', or similar.\n"
        "2) Requests personal details like Full Name, Address, Phone Number.\n"
        "3) Requests Bank Details or payment/processing fees to release winnings.\n"
        "4) Uses strong time pressure (e.g., 'within 24 hours', 'act now', 'forfeit').\n"
        "5) Instructs the recipient to contact a 'claims agent'/'promotion team' immediately.\n\n"
        "Confidence calibration:\n"
        "- 95-99: at least 3 of the scam indicators above are present.\n"
        "- 80-94: exactly 2 scam indicators present.\n"
        "- 60-79: exactly 1 scam indicator present but intent is still suspicious.\n"
        "- <60: weak/unclear indicators; use 'unknown' if you cannot determine.\n\n"
        "If the message asks for credentials via fake login pages/brands, classify as 'phishing'.\n"
        "If the message encourages running/downloading malicious content or 'enable macros', classify as 'malware'.\n"
        "If clearly benign, classify as 'safe'.\n\n"
        "Message:\n"
        f"{text}\n"
    )

    payload = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {"temperature": 0.2},
    }

    resp = requests.post(endpoint, params={"key": api_key}, json=payload, timeout=20)
    resp.raise_for_status()
    data = resp.json()

    text_out = (
        data.get("candidates", [{}])[0]
        .get("content", {})
        .get("parts", [{}])[0]
        .get("text")
    )
    parsed = _parse_gemini_json(text_out)

    category = str(parsed.get("category", "unknown")).lower().strip()
    if category not in _VALID_CATEGORIES:
        category = "unknown"

    summary = str(parsed.get("summary", "")).strip()
    confidence_raw = parsed.get("confidence", 0)
    try:
        confidence = float(confidence_raw)
    except Exception:
        confidence = 0
    confidence = max(0, min(100, int(round(confidence))))
    reason = str(parsed.get("reason", "")).strip()

    # Keep reason shorter if Gemini returns long text.
    reason = re.sub(r"\s+", " ", reason)[:400]

    return {
        "category": category,
        "summary": summary,
        "confidence": confidence,
        "reason": reason,
        "source": "gemini",
    }


def classify(text: str) -> dict[str, Any] | None:
    """
    Returns AI result dict or None if AI is unavailable/fails.
    """
    try:
        return analyze_with_gemini(text)
    except Exception:
        # Caller decides fallback behavior; we intentionally swallow errors here.
        return None
