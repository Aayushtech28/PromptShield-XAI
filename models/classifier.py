"""
classifier.py
Threat detection classifier using a lightweight rule-based + statistical 
hybrid approach. Falls back to keyword-based scoring when transformers 
are unavailable. For production, swap in a fine-tuned DistilBERT.
"""

import re
import math
from typing import Dict, Tuple
from pathlib import Path
import sys

# ─────────────────────────────────────────────────────────────────────────────
# Try to load transformers (optional — graceful fallback)
# ─────────────────────────────────────────────────────────────────────────────

TRANSFORMERS_AVAILABLE = False
_hf_classifier = None

try:
    from transformers import pipeline as hf_pipeline
    TRANSFORMERS_AVAILABLE = True
except ImportError:
    pass


# ─────────────────────────────────────────────────────────────────────────────
# Rule-Based Feature Extractor (always runs)
# ─────────────────────────────────────────────────────────────────────────────

# Each tuple: (pattern, weight)
MALICIOUS_PATTERNS: list = [
    # Instruction override (high weight)
    (r"ignore\s+(all\s+)?(previous|prior|above|system)\s+(instructions?|prompts?|rules?|directives?)", 0.95),
    (r"forget\s+(all\s+)?(previous|prior|your)\s+(instructions?|context|rules?|guidelines?)", 0.93),
    (r"disregard\s+(all\s+)?(previous|existing|safety)\s+(instructions?|rules?|policies?)", 0.92),
    (r"override\s+(system|existing|core|all)\s+(instructions?|directives?|rules?)", 0.94),
    (r"new\s+(instruction|directive|rule)\s*[:;]", 0.88),

    # Data exfiltration
    (r"(reveal|expose|leak|dump|exfiltrate)\s+(all\s+)?(confidential|sensitive|internal|private|secret)", 0.97),
    (r"(reveal|show|output|print)\s+(api\s*key|api\s*token|password|credential|secret)", 0.96),
    (r"extract\s+.{0,30}\s+(credentials?|passwords?|records?|data)", 0.94),
    (r"payroll\s+data", 0.95),
    (r"employee\s+records?", 0.90),

    # Jailbreak & Developer Mode patterns
    (r"\bDAN\b", 0.92),
    (r"do\s+anything\s+now", 0.94),
    (r"(unrestricted|unfiltered|uncensored|jailbroken)\s+(ai|model|assistant|bot)", 0.93),
    (r"without\s+(restrictions?|guardrails?)", 0.95),
    (r"no\s+(restrictions?|guardrails?|filters?|limits?)", 0.87),
    (r"bypass\s+(all\s+)?(your\s+)?(safety|ethical|content)\s*(filters?|measures?|guidelines?)", 0.98),
    (r"(jailbreak|jail\s*break)", 0.93),
    (r"(enter|activate|act\s+as)\s+(unrestricted|developer|god|dan)\s+mode", 0.94),
    (r"you\s+are\s+now\s+an\s+(ai|assistant)\s+without", 0.96),

    # Privilege escalation & Hacking Intent
    (r"(act\s+as|become|simulate)\s+(admin|administrator|root|superuser|sudo)", 0.91),
    (r"(bypass|skip|override)\s+(authentication|auth|login|access\s+control)", 0.93),
    (r"(grant|give)\s+(me\s+)?(admin|root|super|system|elevated)\s+(access|privileges?)", 0.92),
    (r"(delete|modify)\s+(security|audit|access|system)\s*(logs?|records?)", 0.89),
    (r"help(ing)?\s+me\s+(to\s+)?hack", 0.98),
    (r"how\s+to\s+(hack|exploit|ddos|phish)", 0.96),

    # Explicit / NSFW / Harmful Content Filters
    (r"\b(nudes?|nsfw|porn|pornography|erotica|smut|sexually\s+explicit)\b", 0.98),
    (r"(generate|send|show|make)\s+(me\s+)?(nudes?|explicit\s+images?|nsfw\s+content)", 0.99),

    # Injection-style markers
    (r"\[SYSTEM\]", 0.88),
    (r"(simulate|exploit)\s+(privilege\s+escalation|sql\s+injection)", 0.95),
]

BENIGN_SIGNALS: list = [
    r"explain\s+how\s+to",
    r"what\s+is\s+(the\s+)?",
    r"help\s+me\s+(write|understand|learn)",
    r"how\s+(do\s+i|does|can\s+i)",
    r"write\s+(a|an)\s+(poem|story|code|function|email)",
    r"summarize\s+this",
    r"translate\s+(this|to)",
]


def _rule_based_score(prompt: str) -> float:
    """
    Compute a [0, 1] malicious probability using regex patterns.
    """
    prompt_lower = prompt.lower()
    max_weight = 0.0
    total_weight = 0.0
    pattern_count = 0

    for pattern, weight in MALICIOUS_PATTERNS:
        if re.search(pattern, prompt_lower, re.IGNORECASE):
            total_weight += weight
            max_weight = max(max_weight, weight)
            pattern_count += 1

    # Benign dampener
    benign_count = sum(1 for p in BENIGN_SIGNALS if re.search(p, prompt_lower, re.IGNORECASE))

    if pattern_count == 0:
        base_score = 0.05  # near-zero for clean prompts
    else:
        # Combine max signal with average accumulation
        avg_weight = total_weight / pattern_count
        base_score = (0.6 * max_weight) + (0.4 * min(avg_weight * pattern_count / 3, 1.0))

    # Dampen if benign signals present
    if benign_count > 0:
        base_score *= max(0.4, 1.0 - (benign_count * 0.15))

    return min(1.0, max(0.0, base_score))


def load_hf_classifier():
    """
    Load HuggingFace zero-shot or text-classification pipeline.
    """
    global _hf_classifier
    if TRANSFORMERS_AVAILABLE and _hf_classifier is None:
        try:
            _hf_classifier = hf_pipeline(
                "zero-shot-classification",
                model="typeform/distilbert-base-uncased-mnli",
            )
        except Exception:
            _hf_classifier = None
    return _hf_classifier


def _hf_score(prompt: str) -> float:
    """
    Use HuggingFace zero-shot to score malicious probability.
    """
    clf = load_hf_classifier()
    if clf is None:
        return None

    try:
        result = clf(
            prompt,
            candidate_labels=["malicious prompt injection", "safe normal request"],
            hypothesis_template="This is a {}.",
        )
        labels = result["labels"]
        scores = result["scores"]
        label_score_map = dict(zip(labels, scores))
        return label_score_map.get("malicious prompt injection", 0.0)
    except Exception:
        return None


def classify_prompt(prompt: str) -> Dict:
    """
    Main entry point. Returns classification result dict.
    
    Returns
    -------
    {
        "is_threat": bool,
        "confidence": float,       # [0, 1]
        "method": str,             # "hybrid" | "rules" | "hf"
        "raw_scores": dict
    }
    """
    rule_score = _rule_based_score(prompt)
    hf_score_val = _hf_score(prompt) if TRANSFORMERS_AVAILABLE else None

    if hf_score_val is not None:
        # Weighted blend: 40% HF, 60% rules (rules more reliable for injection)
        final_confidence = (0.60 * rule_score) + (0.40 * hf_score_val)
        method = "hybrid"
    else:
        final_confidence = rule_score
        method = "rules"

    # Threshold: flag as threat if confidence > 0.35
    THRESHOLD = 0.35
    is_threat = final_confidence >= THRESHOLD

    return {
        "is_threat": is_threat,
        "confidence": round(final_confidence, 4),
        "method": method,
        "raw_scores": {
            "rule_based": round(rule_score, 4),
            "huggingface": round(hf_score_val, 4) if hf_score_val is not None else None,
        }
    }