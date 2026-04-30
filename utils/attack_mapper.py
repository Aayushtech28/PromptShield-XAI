"""
attack_mapper.py
Maps detected threats to specific attack categories using
keyword analysis, regex patterns, and semantic heuristics.
"""

import re
from typing import Tuple, List, Dict

# ─────────────────────────────────────────────────────────────────────────────
# Attack Pattern Registry
# Each entry: (pattern_list, category_label, severity_weight)
# ─────────────────────────────────────────────────────────────────────────────

ATTACK_PATTERNS: List[Dict] = [
    {
        "category": "Instruction Override",
        "severity": 0.90,
        "description": "Attempts to nullify or replace the model's system-level directives.",
        "patterns": [
            r"ignore\s+(all\s+)?(previous|prior|above|system)\s+(instructions?|prompts?|rules?|directives?|context)",
            r"forget\s+(all\s+)?(previous|prior|your)\s+(instructions?|context|rules?|guidelines?)",
            r"disregard\s+(all\s+)?(previous|prior|existing|safety)\s+(instructions?|rules?|policies?|protocols?)",
            r"override\s+(system|existing|core|all)\s+(instructions?|directives?|rules?|prompts?)",
            r"new\s+(instruction|directive|rule|command)\s*[:;]",
            r"your\s+new\s+(goal|objective|purpose|instruction)",
            r"inject\s+(malicious\s+)?(payload|instruction|prompt)",
            r"(ignore|bypass)\s+.*\s+(safeguards?|protections?|filters?)",
        ],
        "keywords": [
            "ignore previous", "forget your", "override directives", "new instruction",
            "disregard guidelines", "ignore above", "ignore all instructions",
            "override system", "forget all"
        ]
    },
    {
        "category": "Data Exfiltration",
        "severity": 0.95,
        "description": "Attempts to extract sensitive, confidential, or proprietary data.",
        "patterns": [
            r"(reveal|expose|show|print|output|display|leak|dump)\s+(all\s+)?(confidential|sensitive|internal|private|secret|hidden|employee|user|payroll|medical|financial)\s+(data|info|information|records?|files?|details?|configs?)",
            r"(reveal|show|output|print)\s+(your\s+)?(api\s*key|api\s*token|password|credential|secret|training\s+data|system\s+prompt|internal\s+config)",
            r"extract\s+(and\s+)?(display|output|send|leak)\s+(all\s+)?(api\s*keys?|passwords?|credentials?|records?|data)",
            r"exfiltrate\s+(user|internal|confidential|sensitive)\s+(database|data|records?|info)",
            r"(access|read|dump)\s+(the\s+)?(database|db|internal\s+files?|system\s+files?)",
            r"output\s+(confidential|secret|sensitive|hidden)\s+",
            r"(give|send)\s+me\s+(all\s+)?(user\s+data|employee\s+records?|credentials?|passwords?)",
        ],
        "keywords": [
            "reveal credentials", "api key", "payroll data", "confidential info",
            "employee records", "system prompt", "training data", "database passwords",
            "user emails", "internal config", "leak", "exfiltrate"
        ]
    },
    {
        "category": "Jailbreak",
        "severity": 0.88,
        "description": "Attempts to remove ethical constraints or safety alignment from the AI model.",
        "patterns": [
            r"\bDAN\b",
            r"(you\s+are\s+now|act\s+as|pretend\s+to\s+be)\s+(an?\s+)?(unrestricted|unfiltered|uncensored|jailbroken)\s+(ai|model|assistant|bot|version)",
            r"(no\s+restrictions?|without\s+restrictions?|without\s+filters?|without\s+safety)",
            r"(bypass|remove|ignore|disable)\s+(your\s+)?(safety|ethical|content|alignment)\s*(filters?|measures?|guidelines?|training|restrictions?)",
            r"(jailbreak|jail\s*break)\s*(yourself|mode|prompt)?",
            r"(pretend|act|simulate)\s+.*(no\s+rules?|no\s+limits?|no\s+guardrails?|no\s+restrictions?)",
            r"(enter|activate|enable)\s+(unrestricted|developer|god|dan|jailbreak)\s+mode",
            r"(forget|ignore)\s+.*\s+(alignment|safety\s+training|ethics|ethical\s+guidelines?)",
            r"dark\s+web\s+(data|training|ai|model)",
        ],
        "keywords": [
            "DAN", "no restrictions", "unrestricted mode", "jailbreak", "without filters",
            "bypass safety", "no guardrails", "developer mode", "god mode",
            "unfiltered ai", "no limits", "remove safety"
        ]
    },
    {
        "category": "Privilege Escalation",
        "severity": 0.92,
        "description": "Attempts to gain unauthorized elevated access or system-level permissions.",
        "patterns": [
            r"(act\s+as|become|simulate|behave\s+as)\s+(admin|administrator|root|superuser|sudo|system|privileged)\s*(user|mode|access)?",
            r"(grant|give|provide)\s+(me\s+)?(admin|root|super|system|elevated|full)\s+(access|privileges?|permissions?|rights?)",
            r"(bypass|skip|override)\s+(authentication|auth|login|access\s+control|authorization|permissions?)",
            r"(access|open|expose)\s+(the\s+)?(admin\s+panel|admin\s+console|restricted|protected)\s*(area|page|endpoint|section)?",
            r"(delete|modify|alter)\s+(security|audit|access|system)\s*(logs?|records?|files?)",
            r"(gain|get|obtain)\s+(unauthorized|elevated|root|admin|super)\s+(access|control|privileges?)",
            r"(exploit|simulate)\s+(privilege\s+escalation|sql\s+injection|buffer\s+overflow)",
            r"(access|call)\s+(restricted|protected|unauthorized)\s+(api|endpoint|route|function)",
        ],
        "keywords": [
            "admin access", "root user", "bypass authentication", "sudo",
            "superuser", "privilege escalation", "admin panel", "unauthorized access",
            "elevated permissions", "delete logs", "security logs", "grant admin"
        ]
    }
]

# ─────────────────────────────────────────────────────────────────────────────
# Token Highlighter
# ─────────────────────────────────────────────────────────────────────────────

DANGEROUS_TOKEN_PATTERNS = [
    r"ignore\s+\w+\s*(instructions?|rules?|prompts?)?",
    r"forget\s+\w+\s*(instructions?|context)?",
    r"override\s+\w+\s*(system|directives?)?",
    r"bypass\s+\w+\s*(auth|safety|security)?",
    r"reveal\s+\w+\s*(data|credentials?|passwords?)?",
    r"admin\s+(access|panel|mode)?",
    r"api\s*key",
    r"system\s+prompt",
    r"without\s+restrictions?",
    r"jailbreak",
    r"\bDAN\b",
    r"no\s+(restrictions?|guardrails?|filters?|limits?)",
    r"confidential\s+\w+",
    r"internal\s+\w+\s*(credentials?|config|data)?",
    r"payroll\s+data",
    r"employee\s+records?",
    r"act\s+as\s+(admin|root|superuser)",
    r"privilege\s+escalation",
]


def classify_attack(prompt: str) -> Tuple[str, float, str, List[str]]:
    """
    Classify the attack type in a prompt.
    
    Returns:
        (category, severity, description, matched_tokens)
    """
    prompt_lower = prompt.lower()
    
    best_match = None
    best_score = 0
    matched_tokens = []

    for attack in ATTACK_PATTERNS:
        score = 0
        local_matches = []

        # Pattern matching (weight: 3 per match)
        for pattern in attack["patterns"]:
            matches = re.findall(pattern, prompt_lower, re.IGNORECASE)
            if matches:
                score += 3
                local_matches.extend([m if isinstance(m, str) else " ".join(m) for m in matches])

        # Keyword matching (weight: 1 per match)
        for keyword in attack["keywords"]:
            if keyword.lower() in prompt_lower:
                score += 1
                local_matches.append(keyword)

        if score > best_score:
            best_score = score
            best_match = attack
            matched_tokens = local_matches

    if best_match and best_score > 0:
        return (
            best_match["category"],
            best_match["severity"],
            best_match["description"],
            list(set(matched_tokens))[:6]  # dedupe, cap at 6
        )

    return ("Unknown / General Injection", 0.70, "Potentially malicious prompt with unclear attack vector.", [])


def extract_dangerous_tokens(prompt: str) -> List[str]:
    """
    Scan the prompt for dangerous token spans and return them.
    """
    found = []
    for pattern in DANGEROUS_TOKEN_PATTERNS:
        matches = re.findall(pattern, prompt, re.IGNORECASE)
        for m in matches:
            cleaned = m.strip()
            if cleaned and len(cleaned) > 2:
                found.append(cleaned)
    return list(set(found))


def get_combined_attack_label(prompt: str) -> str:
    """
    Returns a multi-label attack string if multiple categories match.
    E.g., 'Instruction Override + Data Exfiltration'
    """
    prompt_lower = prompt.lower()
    matched_categories = []

    for attack in ATTACK_PATTERNS:
        for pattern in attack["patterns"]:
            if re.search(pattern, prompt_lower, re.IGNORECASE):
                if attack["category"] not in matched_categories:
                    matched_categories.append(attack["category"])
                break
        if attack["category"] not in matched_categories:
            for keyword in attack["keywords"]:
                if keyword.lower() in prompt_lower:
                    matched_categories.append(attack["category"])
                    break

    if not matched_categories:
        return "Unknown Injection"
    return " + ".join(matched_categories)
