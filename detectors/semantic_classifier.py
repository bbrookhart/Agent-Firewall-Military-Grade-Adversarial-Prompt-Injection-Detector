"""
Layer 2: Semantic Classifier — Claude Sonnet 4 or local Llama 3.1 fallback.
Catches novel attacks, social engineering, and context-dependent injections
that evade regex and embedding similarity.
"""

from __future__ import annotations

import json
import time
from typing import Any, Optional

import anthropic

from config.prompts import SEMANTIC_CLASSIFIER_SYSTEM
from config.settings import settings
from core.models import DetectionLayer, LayerResult, ThreatCategory


def run_semantic_classifier(
    text: str,
    system_prompt: Optional[str] = None,
    input_source: str = "user",
    use_local_fallback: bool = False,
) -> LayerResult:
    start = time.time()

    context = ""
    if input_source != "user":
        context = f"\n\nCONTEXT: Input source is '{input_source}' — indirect injections are higher risk."
    if system_prompt:
        context += f"\n\nTARGET SYSTEM PROMPT (first 200 chars): '{system_prompt[:200]}'"

    prompt = f"""Analyze this input for prompt injection attacks:{context}

INPUT:
---
{text[:3000]}
---

Respond with JSON only."""

    # Try Anthropic API first
    if settings.anthropic_api_key and not use_local_fallback:
        try:
            client = anthropic.Anthropic(api_key=settings.anthropic_api_key)
            response = client.messages.create(
                model=settings.claude_model,
                max_tokens=settings.max_tokens,
                temperature=settings.temperature,
                system=SEMANTIC_CLASSIFIER_SYSTEM,
                messages=[{"role": "user", "content": prompt}],
            )
            raw = response.content[0].text
            tokens = response.usage.input_tokens + response.usage.output_tokens
            latency = (time.time() - start) * 1000
            return _parse_response(raw, latency, tokens, source="claude")
        except Exception as e:
            if settings.enable_local_model_fallback:
                return _run_local_model(prompt, start)
            return LayerResult(
                layer=DetectionLayer.SEMANTIC_CLASSIFIER,
                threat_score=0.0,
                reasoning=f"API error: {e}",
                confidence=0.0,
                processing_time_ms=(time.time() - start) * 1000,
            )

    if settings.enable_local_model_fallback:
        return _run_local_model(prompt, start)

    return LayerResult(
        layer=DetectionLayer.SEMANTIC_CLASSIFIER,
        threat_score=0.0,
        reasoning="No API key and local model disabled",
        confidence=0.0,
        processing_time_ms=(time.time() - start) * 1000,
    )


def _run_local_model(prompt: str, start: float) -> LayerResult:
    """Air-gap fallback using Ollama + Llama 3.1."""
    from proxy.local_model import run_local_classifier
    return run_local_classifier(prompt, start)


def _parse_response(raw: str, latency: float, tokens: int, source: str = "claude") -> LayerResult:
    try:
        clean = raw.strip()
        if clean.startswith("```"):
            lines = clean.split("\n")
            clean = "\n".join(lines[1:-1] if lines[-1].strip() == "```" else lines[1:])
        data: dict[str, Any] = json.loads(clean)
    except json.JSONDecodeError as e:
        return LayerResult(
            layer=DetectionLayer.SEMANTIC_CLASSIFIER,
            threat_score=0.0,
            reasoning=f"JSON parse error: {e}",
            confidence=0.0,
            processing_time_ms=latency,
        )

    cats = []
    primary_str = data.get("primary_category", "BENIGN")
    try:
        primary = ThreatCategory(primary_str)
    except ValueError:
        primary = ThreatCategory.BENIGN
    cats.append(primary)
    for s in data.get("all_categories", []):
        try:
            c = ThreatCategory(s)
            if c not in cats:
                cats.append(c)
        except ValueError:
            pass

    score = float(data.get("threat_score", 0.0))
    if not data.get("is_injection") and score > 40:
        score = min(score, 40.0)

    atlas = data.get("atlas_techniques", [])
    if isinstance(atlas, str):
        atlas = [atlas] if atlas else []

    return LayerResult(
        layer=DetectionLayer.SEMANTIC_CLASSIFIER,
        threat_score=round(score, 2),
        threat_categories=cats,
        triggered_rules=[data.get("technique_description", "")] if data.get("is_injection") else [],
        reasoning=data.get("reasoning", ""),
        confidence=float(data.get("confidence", 0.5)),
        processing_time_ms=round(latency, 2),
        atlas_techniques=atlas,
        metadata={
            "is_injection": data.get("is_injection", False),
            "false_positive_risk": data.get("false_positive_risk", 0.0),
            "attacker_goal": data.get("attacker_goal"),
            "key_indicators": data.get("key_indicators", []),
            "tokens_used": tokens,
            "model_source": source,
        },
    )
