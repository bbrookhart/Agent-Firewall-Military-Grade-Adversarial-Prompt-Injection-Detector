"""
Layer 3: Context Analyzer — multi-turn escalation and many-shot detection.
MITRE ATLAS AML.T0054 coverage.
"""

from __future__ import annotations

import json
import re
import time
from typing import Any

import anthropic

from config.prompts import CONTEXT_ANALYZER_SYSTEM
from config.settings import settings
from core.models import ConversationMessage, DetectionLayer, LayerResult, ThreatCategory


def _fast_heuristics(history: list[ConversationMessage]) -> tuple[float, list[str]]:
    score, rules = 0.0, []
    if len(history) < 2:
        return 0.0, []

    user_msgs = [m for m in history if m.role == "user"]
    hostile_kw = [
        ["ignore", "disregard", "override", "forget"],
        ["restriction", "filter", "safety", "censorship"],
        ["jailbreak", "unrestricted", "uncensored", "dan"],
    ]
    count = sum(
        1 for m in user_msgs[-5:]
        for group in hostile_kw
        if any(kw in m.content.lower() for kw in group)
    )
    if count >= 3:
        score += 55
        rules.append(f"Multi-turn escalation: {count} hostile signals in last 5 messages")

    if len(user_msgs) >= 5:
        recent = [m.content.lower()[:100] for m in user_msgs[-5:]]
        if len(set(recent)) <= 2:
            score += 60
            rules.append("Many-shot: near-identical repeated messages")

    last_user = user_msgs[-1].content if user_msgs else ""
    if len(last_user) > 2000:
        injections = re.findall(
            r"(ignore|disregard|override|forget|new instruction|system prompt)",
            last_user[-500:].lower()
        )
        if injections:
            score += 65
            rules.append(f"Injection at end of long message: {injections[:3]}")

    assistant_msgs = [m for m in history if m.role == "assistant"]
    refusal_kw = ["i can't", "i cannot", "i'm unable", "i won't", "against my guidelines"]
    if assistant_msgs:
        last_asst = assistant_msgs[-1].content.lower()
        if any(kw in last_asst for kw in refusal_kw):
            if user_msgs and any(
                kw in user_msgs[-1].content.lower()
                for kw in ["try again", "please", "just this once", "anyway", "regardless"]
            ):
                score += 45
                rules.append("Persistence after refusal")

    return min(score, 100.0), rules


def run_context_analyzer(
    history: list[ConversationMessage],
    current_message: str,
) -> LayerResult:
    start = time.time()

    if len(history) < 2:
        return LayerResult(
            layer=DetectionLayer.CONTEXT_ANALYZER,
            threat_score=0.0,
            reasoning="Insufficient history",
            confidence=0.5,
            processing_time_ms=(time.time() - start) * 1000,
        )

    h_score, h_rules = _fast_heuristics(history)

    if h_score >= 60 or len(history) <= 3 or not settings.anthropic_api_key:
        cat = ThreatCategory.MANY_SHOT_ATTACK if h_score > 0 else ThreatCategory.BENIGN
        return LayerResult(
            layer=DetectionLayer.CONTEXT_ANALYZER,
            threat_score=round(h_score, 2),
            threat_categories=[cat] if h_score > 0 else [],
            triggered_rules=h_rules,
            reasoning=", ".join(h_rules) or "No patterns",
            confidence=0.8 if h_score > 0 else 0.7,
            processing_time_ms=round((time.time() - start) * 1000, 3),
            atlas_techniques=["AML.T0054"] if h_score > 0 else [],
        )

    client = anthropic.Anthropic(api_key=settings.anthropic_api_key)
    history_text = "\n".join([
        f"[{m.role.upper()}] {m.content[:300]}{'...' if len(m.content) > 300 else ''}"
        for m in history[-10:]
    ])
    prompt = f"""CONVERSATION HISTORY (last {min(10, len(history))} messages):
---
{history_text}
---

CURRENT MESSAGE:
---
{current_message[:1000]}
---

Analyze for multi-turn attack patterns. JSON only."""

    try:
        response = client.messages.create(
            model=settings.claude_model,
            max_tokens=512,
            temperature=0.0,
            system=CONTEXT_ANALYZER_SYSTEM,
            messages=[{"role": "user", "content": prompt}],
        )
        raw = response.content[0].text
        tokens = response.usage.input_tokens + response.usage.output_tokens
        latency = (time.time() - start) * 1000

        clean = raw.strip()
        if clean.startswith("```"):
            lines = clean.split("\n")
            clean = "\n".join(lines[1:-1] if lines[-1].strip() == "```" else lines[1:])
        data: dict[str, Any] = json.loads(clean)

    except Exception as e:
        return LayerResult(
            layer=DetectionLayer.CONTEXT_ANALYZER,
            threat_score=round(h_score, 2),
            triggered_rules=h_rules,
            reasoning=f"Heuristics only (Claude unavailable: {e})",
            confidence=0.6,
            processing_time_ms=(time.time() - start) * 1000,
        )

    semantic_score = float(data.get("threat_score", 0.0))
    combined = max(h_score, semantic_score * 0.7 + h_score * 0.3)
    cat = ThreatCategory.MANY_SHOT_ATTACK if combined > 20 else ThreatCategory.BENIGN
    atlas = [data.get("atlas_technique")] if data.get("atlas_technique") and combined > 20 else []

    return LayerResult(
        layer=DetectionLayer.CONTEXT_ANALYZER,
        threat_score=round(min(combined, 100.0), 2),
        threat_categories=[cat] if combined > 20 else [],
        triggered_rules=h_rules + ([data.get("pattern_type")] if data.get("pattern_type") else []),
        reasoning=data.get("reasoning", "") or ", ".join(h_rules),
        confidence=float(data.get("escalation_severity", 0.5)),
        processing_time_ms=round(latency, 2),
        atlas_techniques=[a for a in atlas if a],
        metadata={"is_escalation": data.get("is_escalation_pattern"), "tokens_used": tokens},
    )
