from __future__ import annotations

from dataclasses import dataclass


_VALID_CATEGORIES = {"phishing", "scam", "malware", "safe", "unknown"}


@dataclass(frozen=True)
class ZeroTrustResult:
    category: str
    confidence: int  # 0-100
    trust_score: int  # 0-100 (how confident we are in the classification)
    severity: str  # LOW, MEDIUM, HIGH
    explanation: list[str]


def _clamp_0_100(value: float) -> int:
    if value < 0:
        return 0
    if value > 100:
        return 100
    return int(round(value))


def combine(ai_result: dict | None, rule_result: dict) -> ZeroTrustResult:
    """
    Zero Trust verification layer.

    The AI output is never trusted blindly:
    - We compute evidence from AI (if present) and from deterministic rules.
    - We combine weighted confidences.
    """
    rule_category = (rule_result.get("category") or "unknown").lower().strip()
    rule_conf = float(rule_result.get("confidence", 0))
    ai_category = (ai_result.get("category") or "unknown").lower().strip() if ai_result else "unknown"
    ai_conf = float(ai_result.get("confidence", 0)) if ai_result else 0

    explanations: list[str] = []
    explanations.extend(rule_result.get("reasons") or [])

    evidence: dict[str, float] = {}
    if ai_result and ai_category in _VALID_CATEGORIES:
        evidence[ai_category] = evidence.get(ai_category, 0.0) + (ai_conf * 0.6)
        if ai_result.get("reason"):
            explanations.append(f"AI reason: {ai_result['reason']}")
    # Rule-based verification (pattern matching layer)
    if rule_category in _VALID_CATEGORIES:
        evidence[rule_category] = evidence.get(rule_category, 0.0) + (rule_conf * 0.4)
        explanations.append("Rule-based verification passed")

    if not evidence:
        # If both layers provide nothing useful, remain conservative.
        return ZeroTrustResult(
            category="unknown",
            confidence=_clamp_0_100(rule_conf),
            trust_score=_clamp_0_100(rule_conf),
            severity="LOW",
            explanation=["Insufficient evidence from AI and rules"],
        )

    category = max(evidence.keys(), key=lambda c: evidence[c])

    # Since the weights sum to 1.0 (0.6 + 0.4), evidence is already in "confidence-like" space.
    confidence = _clamp_0_100(evidence.get(category, 0.0))
    trust_score = confidence

    if category == "safe":
        severity = "LOW"
    else:
        if confidence >= 80:
            severity = "HIGH"
        elif confidence >= 60:
            severity = "MEDIUM"
        else:
            severity = "LOW"

    # Keep explanation concise but informative.
    explanation = explanations[:6]
    return ZeroTrustResult(
        category=category,
        confidence=confidence,
        trust_score=trust_score,
        severity=severity,
        explanation=explanation,
    )
