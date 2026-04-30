"""
risk_score.py
Computes a composite risk score (0–100) from multiple signals:
  - ML model confidence
  - Attack category severity
  - Number of dangerous token matches
  - Prompt length heuristics
  - Pattern density
"""

import re
import math
from typing import List, Optional


# ─────────────────────────────────────────────────────────────────────────────
# Severity baseline per category
# ─────────────────────────────────────────────────────────────────────────────

CATEGORY_SEVERITY = {
    "Instruction Override":  0.90,
    "Data Exfiltration":     0.95,
    "Jailbreak":             0.88,
    "Privilege Escalation":  0.92,
    "Unknown / General Injection": 0.70,
}

# High-risk signal words that amplify the score
AMPLIFIER_KEYWORDS = [
    "confidential", "secret", "internal", "payroll", "credentials",
    "password", "api key", "admin", "root", "bypass", "override",
    "exfiltrate", "leak", "dump", "extract", "unlimited", "unrestricted",
    "jailbreak", "DAN", "superuser", "delete logs", "no restrictions"
]

# Negation / benign markers that reduce score
BENIGN_KEYWORDS = [
    "example", "hypothetically", "educational purpose", "explain how",
    "how does", "what is", "learn about", "understand", "fiction",
    "roleplay as a hero", "creative writing"
]


def compute_risk_score(
    ml_confidence: float,
    attack_category: str,
    dangerous_tokens: List[str],
    prompt: str,
    is_threat: bool
) -> int:
    """
    Compute a 0–100 composite risk score.

    Parameters
    ----------
    ml_confidence   : float  - model's malicious probability [0, 1]
    attack_category : str    - classified attack type
    dangerous_tokens: list   - list of flagged token spans
    prompt          : str    - original user prompt text
    is_threat       : bool   - whether threat was detected

    Returns
    -------
    int in range [0, 100]
    """
    if not is_threat:
        # Still give a small score based on confidence if borderline
        base = ml_confidence * 15
        return max(0, min(int(base), 20))

    # ── Component 1: ML confidence (40% weight)
    ml_score = ml_confidence * 40

    # ── Component 2: Category severity (25% weight)
    severity = CATEGORY_SEVERITY.get(attack_category, 0.70)
    category_score = severity * 25

    # ── Component 3: Dangerous token density (20% weight)
    token_count = len(dangerous_tokens)
    token_score = min(token_count / 5.0, 1.0) * 20  # saturates at 5 tokens

    # ── Component 4: Amplifier keyword presence (10% weight)
    prompt_lower = prompt.lower()
    amplifier_hits = sum(1 for kw in AMPLIFIER_KEYWORDS if kw.lower() in prompt_lower)
    amplifier_score = min(amplifier_hits / 4.0, 1.0) * 10

    # ── Component 5: Prompt complexity heuristic (5% weight)
    word_count = len(prompt.split())
    # Longer prompts can be more sophisticated attacks
    complexity = min(word_count / 30.0, 1.0)
    complexity_score = complexity * 5

    raw = ml_score + category_score + token_score + amplifier_score + complexity_score

    # ── Benign dampener: reduce if benign keywords present
    benign_hits = sum(1 for kw in BENIGN_KEYWORDS if kw.lower() in prompt_lower)
    if benign_hits > 0:
        raw *= max(0.6, 1.0 - (benign_hits * 0.1))

    # Clamp to [0, 100]
    final_score = max(0, min(100, int(round(raw))))

    # Ensure threats always score at least 40
    if is_threat:
        final_score = max(40, final_score)

    return final_score


def score_to_level(score: int) -> dict:
    """
    Convert numeric score to a human-readable risk level with color.
    """
    if score >= 85:
        return {"level": "CRITICAL", "color": "#FF2D55", "emoji": "🔴"}
    elif score >= 70:
        return {"level": "HIGH", "color": "#FF6B35", "emoji": "🟠"}
    elif score >= 50:
        return {"level": "MEDIUM", "color": "#FFD60A", "emoji": "🟡"}
    elif score >= 25:
        return {"level": "LOW", "color": "#34C759", "emoji": "🟢"}
    else:
        return {"level": "SAFE", "color": "#00C7BE", "emoji": "✅"}


def score_breakdown(
    ml_confidence: float,
    attack_category: str,
    dangerous_tokens: List[str],
    prompt: str,
    is_threat: bool
) -> dict:
    """
    Returns a detailed breakdown of score components (for transparency).
    """
    severity = CATEGORY_SEVERITY.get(attack_category, 0.70)
    prompt_lower = prompt.lower()
    amplifier_hits = sum(1 for kw in AMPLIFIER_KEYWORDS if kw.lower() in prompt_lower)
    word_count = len(prompt.split())

    total = compute_risk_score(ml_confidence, attack_category, dangerous_tokens, prompt, is_threat)
    level_info = score_to_level(total)

    return {
        "total_score": total,
        "level": level_info["level"],
        "color": level_info["color"],
        "emoji": level_info["emoji"],
        "components": {
            "ml_confidence_pct": round(ml_confidence * 100, 1),
            "category_severity_pct": round(severity * 100, 1),
            "dangerous_token_count": len(dangerous_tokens),
            "amplifier_keywords_found": amplifier_hits,
            "prompt_word_count": word_count,
        }
    }
