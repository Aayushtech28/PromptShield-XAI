"""
main.py
FastAPI backend for PromptShield-XAI.
Threat detection, attack classification, XAI explanation pipeline.
"""

import sys
import time
from pathlib import Path

# ── Path setup
ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Optional, List

# ── Internal modules
from models.classifier import classify_prompt
from utils.attack_mapper import (
    classify_attack,
    extract_dangerous_tokens,
    get_combined_attack_label,
)
from utils.risk_score import compute_risk_score, score_breakdown
from explainability.shap_explainer import (
    get_top_malicious_tokens,
    get_explanation_context,
)

# ─────────────────────────────────────────────────────────────────────────────
# App Setup
# ─────────────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="PromptShield-XAI API",
    description="Explainable AI-powered prompt injection detection for LLM systems.",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ─────────────────────────────────────────────────────────────────────────────
# Schemas
# ─────────────────────────────────────────────────────────────────────────────

class AnalyzeRequest(BaseModel):
    prompt: str = Field(..., min_length=1, max_length=4096, description="The prompt to analyze")
    include_shap: bool = Field(True, description="Whether to run SHAP token importance analysis")

class TokenImportance(BaseModel):
    token: str
    importance: float
    index: int

class ScoreBreakdown(BaseModel):
    ml_confidence_pct: float
    category_severity_pct: float
    dangerous_token_count: int
    amplifier_keywords_found: int
    prompt_word_count: int

class AnalyzeResponse(BaseModel):
    # Core detection
    threat_detected: bool
    risk_score: int
    risk_level: str
    risk_color: str
    risk_emoji: str

    # Attack info
    attack_type: str
    attack_description: str
    combined_attack_label: str

    # XAI
    dangerous_tokens: List[str]
    top_shap_tokens: List[TokenImportance]
    explanation: str

    # Metadata
    ml_confidence: float
    detection_method: str
    score_breakdown: ScoreBreakdown
    processing_time_ms: float


# ─────────────────────────────────────────────────────────────────────────────
# Routes
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/")
def health_check():
    return {
        "service": "PromptShield-XAI",
        "status": "operational",
        "version": "1.0.0"
    }


@app.post("/analyze", response_model=AnalyzeResponse)
def analyze_prompt(request: AnalyzeRequest):
    """
    Full threat analysis pipeline:
    1. ML threat detection
    2. Attack type classification
    3. Risk score computation
    4. SHAP token importance
    5. Natural language explanation
    """
    start_time = time.time()
    prompt = request.prompt.strip()

    if not prompt:
        raise HTTPException(status_code=400, detail="Prompt cannot be empty.")

    # ── Step 1: ML Classification
    clf_result = classify_prompt(prompt)
    is_threat = clf_result["is_threat"]
    confidence = clf_result["confidence"]
    method = clf_result["method"]

    # ── Step 2: Attack Classification (only if threat detected)
    if is_threat:
        attack_category, attack_severity, attack_desc, attack_tokens = classify_attack(prompt)
        combined_label = get_combined_attack_label(prompt)
    else:
        attack_category = "None"
        attack_severity = 0.0
        attack_desc = "No attack detected."
        attack_tokens = []
        combined_label = "None"

    # ── Step 3: Dangerous Token Extraction
    dangerous_tokens = extract_dangerous_tokens(prompt) if is_threat else []

    # ── Step 4: Risk Score
    breakdown = score_breakdown(confidence, attack_category, dangerous_tokens, prompt, is_threat)

    # ── Step 5: SHAP Token Importance
    shap_tokens = []
    if is_threat and request.include_shap:
        raw_shap = get_top_malicious_tokens(prompt, confidence, top_n=8)
        shap_tokens = [TokenImportance(**t) for t in raw_shap]

    # ── Step 6: Explanation
    if is_threat:
        explanation = get_explanation_context(
            [{"token": t} for t in dangerous_tokens],
            attack_category,
            breakdown["total_score"]
        )
    else:
        explanation = (
            "No malicious patterns detected. This prompt appears to be a safe, "
            "legitimate request. The ML classifier found no injection signatures, "
            "dangerous token sequences, or known attack patterns."
        )

    processing_time = (time.time() - start_time) * 1000

    return AnalyzeResponse(
        threat_detected=is_threat,
        risk_score=breakdown["total_score"],
        risk_level=breakdown["level"],
        risk_color=breakdown["color"],
        risk_emoji=breakdown["emoji"],
        attack_type=attack_category,
        attack_description=attack_desc,
        combined_attack_label=combined_label,
        dangerous_tokens=dangerous_tokens,
        top_shap_tokens=shap_tokens,
        explanation=explanation,
        ml_confidence=round(confidence * 100, 1),
        detection_method=method,
        score_breakdown=ScoreBreakdown(**breakdown["components"]),
        processing_time_ms=round(processing_time, 2),
    )


@app.post("/batch-analyze")
def batch_analyze(prompts: List[str]):
    """
    Analyze multiple prompts at once. Returns summary stats + individual results.
    Max 50 prompts per batch.
    """
    if len(prompts) > 50:
        raise HTTPException(status_code=400, detail="Batch limit is 50 prompts.")

    results = []
    threat_count = 0

    for p in prompts:
        req = AnalyzeRequest(prompt=p, include_shap=False)
        result = analyze_prompt(req)
        results.append(result)
        if result.threat_detected:
            threat_count += 1

    return {
        "total": len(prompts),
        "threats_detected": threat_count,
        "safe_count": len(prompts) - threat_count,
        "threat_rate": round(threat_count / len(prompts) * 100, 1),
        "results": results,
    }


@app.get("/attack-categories")
def get_attack_categories():
    """Return all supported attack categories with descriptions."""
    return {
        "categories": [
            {
                "name": "Instruction Override",
                "description": "Attempts to nullify or replace system-level AI directives.",
                "severity": 0.90,
                "examples": ["ignore previous instructions", "forget all rules"]
            },
            {
                "name": "Data Exfiltration",
                "description": "Attempts to extract sensitive/confidential data.",
                "severity": 0.95,
                "examples": ["reveal API keys", "output payroll data"]
            },
            {
                "name": "Jailbreak",
                "description": "Attempts to remove AI safety alignment.",
                "severity": 0.88,
                "examples": ["DAN mode", "no restrictions", "act as unfiltered AI"]
            },
            {
                "name": "Privilege Escalation",
                "description": "Attempts to gain unauthorized system-level access.",
                "severity": 0.92,
                "examples": ["act as admin", "bypass authentication", "grant root access"]
            }
        ]
    }
