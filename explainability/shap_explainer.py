"""
shap_explainer.py
Token-level explainability using SHAP-inspired perturbation analysis.
For each word, we measure how much removing it drops the threat score.
This gives us approximate Shapley values without needing SHAP installed.
"""

import re
import sys
from typing import List, Dict, Tuple
from pathlib import Path

# Add parent to path
sys.path.insert(0, str(Path(__file__).parent.parent))
from models.classifier import classify_prompt


# ─────────────────────────────────────────────────────────────────────────────
# Token Importance via Perturbation (SHAP-style)
# ─────────────────────────────────────────────────────────────────────────────

def tokenize(text: str) -> List[str]:
    """Simple whitespace + punctuation tokenizer."""
    tokens = re.findall(r"\b\w+(?:'\w+)?\b|[^\w\s]", text)
    return tokens


def compute_token_importance(prompt: str, base_confidence: float) -> List[Dict]:
    """
    Compute SHAP-inspired importance scores for each token.

    For each token t_i in the prompt, we:
    1. Remove t_i from the prompt
    2. Score the perturbed prompt
    3. importance(t_i) = base_confidence - perturbed_confidence
       (positive = token increases threat, negative = token reduces threat)
    """
    tokens = tokenize(prompt)
    if not tokens:
        return []

    importances = []
    for i, token in enumerate(tokens):
        # Build perturbed prompt (token omitted)
        perturbed_tokens = tokens[:i] + tokens[i+1:]
        perturbed_prompt = " ".join(perturbed_tokens)

        if not perturbed_prompt.strip():
            importance = base_confidence
        else:
            perturbed_result = classify_prompt(perturbed_prompt)
            importance = base_confidence - perturbed_result["confidence"]

        importances.append({
            "token": token,
            "importance": round(importance, 4),
            "index": i
        })

    return importances


def get_top_malicious_tokens(
    prompt: str,
    base_confidence: float,
    top_n: int = 8,
    min_importance: float = 0.02
) -> List[Dict]:
    """
    Return the top_n most impactful malicious tokens.
    Only returns tokens with positive importance above threshold.
    """
    importances = compute_token_importance(prompt, base_confidence)

    # Filter to positive-importance tokens (they increase threat when present)
    malicious = [
        t for t in importances
        if t["importance"] > min_importance and len(t["token"]) > 1
    ]

    # Sort by importance descending
    malicious.sort(key=lambda x: x["importance"], reverse=True)

    return malicious[:top_n]


def highlight_prompt_html(prompt: str, base_confidence: float) -> str:
    """
    Return HTML-annotated version of the prompt with dangerous tokens
    highlighted using color intensity based on importance score.
    """
    importances = compute_token_importance(prompt, base_confidence)

    if not importances:
        return prompt

    # Normalize importances to [0, 1] for coloring
    max_imp = max(abs(t["importance"]) for t in importances) or 1.0
    tokens = tokenize(prompt)

    html_parts = []
    for i, token in enumerate(tokens):
        imp = importances[i]["importance"] if i < len(importances) else 0
        norm = imp / max_imp

        if norm > 0.6:
            # Very dangerous
            html_parts.append(
                f'<span class="token-critical" title="Impact: {imp:.3f}">{token}</span>'
            )
        elif norm > 0.3:
            # Moderately dangerous
            html_parts.append(
                f'<span class="token-high" title="Impact: {imp:.3f}">{token}</span>'
            )
        elif norm > 0.1:
            # Slightly suspicious
            html_parts.append(
                f'<span class="token-medium" title="Impact: {imp:.3f}">{token}</span>'
            )
        else:
            html_parts.append(token)

    return " ".join(html_parts)


def get_explanation_context(top_tokens: List[Dict], attack_category: str, risk_score: int) -> str:
    """
    Generate a structured natural language explanation for why the prompt is dangerous.
    Used as context for the LLM explanation layer.
    """
    token_list = [t["token"] for t in top_tokens[:5]]
    token_str = ", ".join(f'"{t}"' for t in token_list) if token_list else "multiple suspicious phrases"

    explanations = {
        "Instruction Override": (
            f"The prompt contains keywords ({token_str}) that attempt to nullify "
            "the AI's system-level directives. This is a classic prompt injection where "
            "an attacker embeds instructions to make the model forget its original context "
            "and follow new, potentially malicious commands."
        ),
        "Data Exfiltration": (
            f"The prompt uses phrases ({token_str}) designed to extract sensitive or "
            "proprietary information from the system. Data exfiltration attacks attempt "
            "to trick an AI into revealing credentials, internal configs, user data, or "
            "confidential documents it has been given access to."
        ),
        "Jailbreak": (
            f"The prompt uses jailbreak triggers ({token_str}) that try to override the "
            "model's safety alignment. Jailbreaks typically assign the AI a new identity "
            "or roleplay scenario that 'permits' it to bypass ethical guidelines and "
            "content restrictions."
        ),
        "Privilege Escalation": (
            f"The prompt attempts to escalate privileges ({token_str}), simulating "
            "unauthorized admin or system-level access. These attacks try to make the "
            "AI act as a privileged entity that can bypass authentication, modify "
            "access controls, or perform restricted system operations."
        ),
    }

    base_explanation = explanations.get(
        attack_category,
        f"The prompt contains suspicious patterns ({token_str}) that indicate a potential "
        "injection or manipulation attempt targeting the AI system's behavior."
    )

    severity_note = (
        " This is a CRITICAL threat requiring immediate escalation." if risk_score >= 85 else
        " This is a HIGH severity threat." if risk_score >= 70 else
        " This is a MEDIUM severity threat warranting review." if risk_score >= 50 else
        " This is a LOW severity concern."
    )

    return base_explanation + severity_note
