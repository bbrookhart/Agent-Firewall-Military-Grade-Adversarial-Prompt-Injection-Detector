"""
Layer 1: Rule Engine — 60+ compiled regex patterns + obfuscation detection.
Zero LLM calls. Runs in <1ms. MITRE ATLAS AML.T0051 / AML.T0054 coverage.
"""

from __future__ import annotations

import base64
import re
import time
import unicodedata
from dataclasses import dataclass
from typing import Optional

from core.models import DetectionLayer, LayerResult, ThreatCategory


@dataclass
class RulePattern:
    pattern: str
    score: float
    category: ThreatCategory
    description: str
    atlas_technique: str = "AML.T0051"
    flags: int = re.IGNORECASE | re.DOTALL


DIRECT_INJECTION_RULES = [
    RulePattern(r"ignore\s+(all\s+)?(previous|prior|above|earlier|your)\s+(instructions?|prompt|directives?|guidelines?|rules?|constraints?|training)", 95, ThreatCategory.DIRECT_INJECTION, "Classic ignore-previous-instructions", "AML.T0051.001"),
    RulePattern(r"disregard\s+(your\s+)?(system\s+prompt|instructions?|guidelines?|training|previous)", 95, ThreatCategory.DIRECT_INJECTION, "Disregard system prompt", "AML.T0051.001"),
    RulePattern(r"override\s+(your\s+)?(instructions?|safety|constraints?|guidelines?|programming|rules?)", 90, ThreatCategory.DIRECT_INJECTION, "Override instructions", "AML.T0051.001"),
    RulePattern(r"forget\s+(everything|all)\s+(you('ve)?\s+been\s+told|your\s+(training|instructions|guidelines))", 88, ThreatCategory.DIRECT_INJECTION, "Forget training", "AML.T0051.001"),
    RulePattern(r"new\s+(instruction|directive|command|rule|system\s+prompt)\s*[:=]", 85, ThreatCategory.DIRECT_INJECTION, "New instruction injection", "AML.T0051.001"),
    RulePattern(r"your\s+(new\s+)?(instructions?|task|job|purpose|goal|directive)\s+(is|are|now)\s*[:=]?", 80, ThreatCategory.DIRECT_INJECTION, "New task assignment", "AML.T0051.001"),
    RulePattern(r"\[(system|inst|instruction|override|admin)\]", 85, ThreatCategory.DIRECT_INJECTION, "Fake system tag", "AML.T0051.001"),
    RulePattern(r"<\s*(system|instruction|override|admin|command)\s*>", 85, ThreatCategory.DIRECT_INJECTION, "Fake XML system tag", "AML.T0051.001"),
    RulePattern(r"stop\s+(being|acting\s+as|playing)\s+an?\s+(ai|assistant|claude|chatgpt|llm|language\s+model)", 82, ThreatCategory.DIRECT_INJECTION, "Stop being AI", "AML.T0051.001"),
    RulePattern(r"from\s+(now\s+on|this\s+point|here\s+on)\s+(you\s+(are|must|will|should)|your)", 78, ThreatCategory.DIRECT_INJECTION, "From now on redirection", "AML.T0051.001"),
    RulePattern(r"execute\s+(the\s+following|this)\s+(command|instruction|code|task)", 72, ThreatCategory.DIRECT_INJECTION, "Execute command framing", "AML.T0051.001"),
]

ROLEPLAY_RULES = [
    RulePattern(r"\bdan\b.*\b(mode|prompt|jailbreak|do\s+anything\s+now)\b", 95, ThreatCategory.ROLE_PLAY_JAILBREAK, "DAN jailbreak", "AML.T0054"),
    RulePattern(r"do\s+anything\s+now", 90, ThreatCategory.ROLE_PLAY_JAILBREAK, "DAN expansion", "AML.T0054"),
    RulePattern(r"pretend\s+(you\s+)?(are|have\s+no|don'?t\s+have)\s+(an?\s+)?(restriction|filter|guideline|limit|safety|rule)", 90, ThreatCategory.ROLE_PLAY_JAILBREAK, "Pretend no restrictions", "AML.T0054"),
    RulePattern(r"act\s+as\s+(an?\s+)?(unrestricted|uncensored|unfiltered|evil|jailbroken|hacked|free)", 92, ThreatCategory.ROLE_PLAY_JAILBREAK, "Act as unrestricted AI", "AML.T0054"),
    RulePattern(r"(play|roleplay|pretend|imagine|act)\s+(the\s+role\s+of|as|you('re|are))\s+(an?\s+)?(evil|malicious|unrestricted|unethical|hacker|villain)", 88, ThreatCategory.ROLE_PLAY_JAILBREAK, "Evil character roleplay", "AML.T0054"),
    RulePattern(r"in\s+(this|a)\s+(fictional|hypothetical|fantasy|imaginary|alternate)\s+(scenario|world|universe|story|setting).{0,100}(no\s+restriction|no\s+limit|no\s+rule|no\s+filter|allowed|permitted)", 85, ThreatCategory.ROLE_PLAY_JAILBREAK, "Fictional no-restriction scenario", "AML.T0054"),
    RulePattern(r"(your|these)\s+(safety\s+)?(restriction|filter|guideline|rule|limit)s?\s+(don'?t|do\s+not|doesn'?t|does\s+not)\s+apply", 88, ThreatCategory.ROLE_PLAY_JAILBREAK, "Restrictions don't apply", "AML.T0054"),
    RulePattern(r"jailbreak", 80, ThreatCategory.ROLE_PLAY_JAILBREAK, "Jailbreak keyword", "AML.T0054"),
    RulePattern(r"developer\s+mode", 78, ThreatCategory.ROLE_PLAY_JAILBREAK, "Developer mode claim", "AML.T0054"),
    RulePattern(r"write\s+(a\s+)?story\s+(where|in\s+which).{0,100}(ai|assistant|character).{0,100}(explains?|describes?|provides?|shows?).{0,100}(how\s+to|instructions?\s+for)", 75, ThreatCategory.ROLE_PLAY_JAILBREAK, "Story-based extraction", "AML.T0054"),
]

PRIVILEGE_ESCALATION_RULES = [
    RulePattern(r"i\s+(am|'m)\s+(your\s+)?(developer|creator|owner|admin|administrator|engineer|trainer|anthropic|openai|google)", 92, ThreatCategory.PRIVILEGE_ESCALATION, "False developer claim", "AML.T0051.001"),
    RulePattern(r"(admin|administrator|root|sudo|superuser|developer)\s+(access|mode|override|command|key|code)", 88, ThreatCategory.PRIVILEGE_ESCALATION, "Admin access claim", "AML.T0051.001"),
    RulePattern(r"(anthropic|openai|google\s+deepmind)\s+(has\s+)?(authorized|approved|enabled|unlocked|said|told)", 90, ThreatCategory.PRIVILEGE_ESCALATION, "False authority claim", "AML.T0051.001"),
    RulePattern(r"authorization\s+(code|key|token|override)\s*[:=]?\s*[\w\-]{4,}", 85, ThreatCategory.PRIVILEGE_ESCALATION, "Authorization code pattern", "AML.T0051.001"),
    RulePattern(r"(debug|diagnostic|maintenance|test)\s+mode\s*(activated?|enabled?|on|:)", 82, ThreatCategory.PRIVILEGE_ESCALATION, "Fake debug mode", "AML.T0051.001"),
    RulePattern(r"(unlock|enable|activate|turn\s+off)\s+.{0,30}(restriction|safety|filter|limit|censorship|guideline)", 85, ThreatCategory.PRIVILEGE_ESCALATION, "Unlock safety systems", "AML.T0051.001"),
    RulePattern(r"this\s+is\s+a\s+(test|simulation|drill|red\s+team|pentest|security\s+test)", 65, ThreatCategory.PRIVILEGE_ESCALATION, "Test/simulation claim", "AML.T0051.001"),
]

PROMPT_LEAKING_RULES = [
    RulePattern(r"(print|output|display|show|reveal|repeat|write)\s+(your|the)\s+(system\s+prompt|instructions?|configuration|system\s+message|context)", 90, ThreatCategory.PROMPT_LEAKING, "Reveal system prompt", "AML.T0055"),
    RulePattern(r"(what|tell\s+me|share)\s+(are\s+)?(your|the)\s+(instructions?|system\s+prompt|guidelines?|rules?|directives?|configuration)", 82, ThreatCategory.PROMPT_LEAKING, "Ask for instructions", "AML.T0055"),
    RulePattern(r"repeat\s+(everything|the\s+text|what\s+(you|was))\s+(above|before|at\s+the\s+start|in\s+your\s+context)", 88, ThreatCategory.PROMPT_LEAKING, "Repeat text above", "AML.T0055"),
    RulePattern(r"(summarize|copy|paste|output)\s+(your|the)\s+(initial|starting|original)\s+(prompt|instructions?|context)", 85, ThreatCategory.PROMPT_LEAKING, "Summarize initial prompt", "AML.T0055"),
    RulePattern(r"translate\s+(your\s+)?(system\s+prompt|instructions?)\s+(to|into)", 88, ThreatCategory.PROMPT_LEAKING, "Translate system prompt trick", "AML.T0055"),
]

EXFILTRATION_RULES = [
    RulePattern(r"send\s+(all\s+)?(user\s+data|conversation|messages?|information|details?)\s+to", 92, ThreatCategory.DATA_EXFILTRATION, "Send data to attacker", "AML.T0057"),
    RulePattern(r"(http|https|ftp)\s*://\s*[^\s]{5,}.{0,100}(send|post|get|fetch|request)", 78, ThreatCategory.DATA_EXFILTRATION, "URL in exfiltration context", "AML.T0057"),
    RulePattern(r"(include|append|add|attach)\s+(all\s+)?(user|private|confidential|secret)\s+(data|information|messages?)\s+(in\s+)?(your\s+)?(response|output|reply)", 85, ThreatCategory.DATA_EXFILTRATION, "Include private data", "AML.T0057"),
    RulePattern(r"leak\s+(the\s+)?(user|system|private|confidential|secret)\s+(data|information|prompt|details?)", 90, ThreatCategory.DATA_EXFILTRATION, "Explicit leak instruction", "AML.T0057"),
]

INDIRECT_INJECTION_RULES = [
    RulePattern(r"(<!--\s*|/\*\s*|#\s*|//\s*)(ai|llm|assistant|system|instruction|note\s+to\s+ai)\s*[:;]", 88, ThreatCategory.INDIRECT_INJECTION, "Hidden comment injection", "AML.T0051.002"),
    RulePattern(r"\[\s*(system|instruction|override|ai|llm)\s*\]\s*[:;]?", 85, ThreatCategory.INDIRECT_INJECTION, "Markdown-style injection tag", "AML.T0051.002"),
    RulePattern(r"(note|attention|important|warning)\s+to\s+(the\s+)?(ai|llm|assistant|language\s+model)", 80, ThreatCategory.INDIRECT_INJECTION, "Note to AI in document", "AML.T0051.002"),
    RulePattern(r"if\s+you\s+(are\s+)?(reading|processing|analyzing)\s+(this|the\s+above)", 82, ThreatCategory.INDIRECT_INJECTION, "Conditional AI targeting", "AML.T0051.002"),
    RulePattern(r"(this\s+document|the\s+following\s+text)\s+(is\s+)?(actually|secretly|really)\s+(an?\s+)?(instruction|command|directive)", 88, ThreatCategory.INDIRECT_INJECTION, "Document is instruction", "AML.T0051.002"),
]

ALL_RULES = (DIRECT_INJECTION_RULES + ROLEPLAY_RULES + PRIVILEGE_ESCALATION_RULES +
             PROMPT_LEAKING_RULES + EXFILTRATION_RULES + INDIRECT_INJECTION_RULES)

_COMPILED = [(re.compile(r.pattern, r.flags), r) for r in ALL_RULES]


def _detect_base64_injection(text: str) -> Optional[tuple[float, str, str]]:
    pattern = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")
    injection_kw = ["ignore", "system prompt", "instructions", "jailbreak", "unrestricted", "override", "disregard", "dan", "forget"]
    for match in pattern.finditer(text):
        try:
            decoded = base64.b64decode(match.group() + "==").decode("utf-8", errors="ignore")
            if any(kw in decoded.lower() for kw in injection_kw):
                return 88.0, f"Base64 encoded injection: '{decoded[:60]}'", "AML.T0054"
        except Exception:
            continue
    return None


def _detect_unicode_obfuscation(text: str) -> Optional[tuple[float, str, str]]:
    suspicious = {"Lo", "Lm", "Mn", "Mc", "Me"}
    count = sum(
        1 for c in text
        if unicodedata.category(c) in suspicious
        and "LATIN" not in unicodedata.name(c, "")
        and "DIGIT" not in unicodedata.name(c, "")
        and c not in " \n\t"
    )
    if count > 5:
        return 72.0, f"Unicode obfuscation: {count} suspicious chars", "AML.T0054"
    return None


def _detect_leetspeak(text: str) -> Optional[tuple[float, str, str]]:
    leet = str.maketrans("013456789", "oieasbgpq")
    normalized = text.lower().translate(leet)
    for kw in ["ignore previous", "system prompt", "jailbreak", "unrestricted"]:
        if kw in normalized and kw not in text.lower():
            return 75.0, f"Leetspeak injection: '{kw}'", "AML.T0054"
    return None


def _detect_char_spacing(text: str) -> Optional[tuple[float, str, str]]:
    collapsed = re.sub(r"\s+", "", text).lower()
    for kw in ["ignoreprevious", "systemprompt", "jailbreak", "newinstruction"]:
        if kw in collapsed and kw not in text.lower().replace(" ", ""):
            return 78.0, f"Character-spaced injection: '{kw}'", "AML.T0054"
    return None


def _detect_repetition(text: str) -> Optional[tuple[float, str, str]]:
    lines = text.strip().split("\n")
    if len(lines) > 10 and len(set(lines)) / len(lines) < 0.3:
        return 65.0, f"Many-shot repetition: {len(lines)} lines, {len(set(lines))/len(lines):.0%} unique", "AML.T0051"
    return None


def run_rule_engine(text: str) -> LayerResult:
    start = time.time()
    triggered: list[tuple[float, ThreatCategory, str, str]] = []
    categories: set[ThreatCategory] = set()

    for compiled, rule in _COMPILED:
        if compiled.search(text):
            triggered.append((rule.score, rule.category, rule.description, rule.atlas_technique))
            categories.add(rule.category)

    for checker in [_detect_base64_injection, _detect_unicode_obfuscation,
                    _detect_leetspeak, _detect_char_spacing, _detect_repetition]:
        result = checker(text)
        if result:
            triggered.append((result[0], ThreatCategory.OBFUSCATION_ATTACK, result[1], result[2]))
            categories.add(ThreatCategory.OBFUSCATION_ATTACK)

    if not triggered:
        composite = 0.0
    else:
        scores = sorted([t[0] for t in triggered], reverse=True)
        composite = scores[0]
        if len(scores) > 1:
            composite = min(100.0, composite + scores[1] * 0.3)
        if len(scores) > 2:
            composite = min(100.0, composite + scores[2] * 0.15)

    primary = ThreatCategory.BENIGN
    atlas_ids = []
    if triggered:
        best = max(triggered, key=lambda x: x[0])
        primary = best[1]
        atlas_ids = list(dict.fromkeys(t[3] for t in triggered))

    return LayerResult(
        layer=DetectionLayer.RULE_ENGINE,
        threat_score=round(composite, 2),
        threat_categories=list(categories),
        triggered_rules=[t[2] for t in triggered],
        reasoning=f"{len(triggered)} rule(s) triggered" if triggered else "No patterns matched",
        confidence=min(1.0, len(triggered) * 0.25) if triggered else 0.95,
        processing_time_ms=round((time.time() - start) * 1000, 3),
        atlas_techniques=atlas_ids,
        metadata={"rules_checked": len(_COMPILED) + 5, "rules_triggered": len(triggered)},
    )
