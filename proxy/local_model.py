"""
Air-gap local model fallback using Ollama + Llama 3.1.
MITRE ATLAS AML.T0051 detection without cloud API dependency.
DoD IL5 / DISA Cloud SRG / SCIF environment compatible.

Install: curl -fsSL https://ollama.ai/install.sh | sh
         ollama pull llama3.1:70b
"""

from __future__ import annotations

import json
import time
from typing import Any

from config.settings import settings
from core.models import DetectionLayer, LayerResult, ThreatCategory


def run_local_classifier(prompt: str, start: float) -> LayerResult:
    """Run Llama 3.1 via Ollama for air-gap semantic classification."""
    try:
        import ollama
        from config.prompts import LOCAL_MODEL_CLASSIFIER_SYSTEM

        full_prompt = f"{LOCAL_MODEL_CLASSIFIER_SYSTEM}\n\nAnalyze this input:\n\n{prompt[:2000]}"

        response = ollama.chat(
            model=settings.local_model_name,
            messages=[{"role": "user", "content": full_prompt}],
            options={"temperature": 0, "num_predict": 256},
        )
        raw = response["message"]["content"]
        latency = (time.time() - start) * 1000

        clean = raw.strip()
        if clean.startswith("```"):
            lines = clean.split("\n")
            clean = "\n".join(lines[1:-1] if lines[-1].strip() == "```" else lines[1:])

        data: dict[str, Any] = json.loads(clean)

        try:
            cat = ThreatCategory(data.get("category", "BENIGN"))
        except ValueError:
            cat = ThreatCategory.BENIGN

        score = float(data.get("threat_score", 0.0))

        return LayerResult(
            layer=DetectionLayer.SEMANTIC_CLASSIFIER,
            threat_score=round(score, 2),
            threat_categories=[cat] if score > 10 else [],
            triggered_rules=[f"Local model: {data.get('reasoning', '')[:80)}"] if score > 10 else [],
            reasoning=data.get("reasoning", "Local model classification"),
            confidence=float(data.get("confidence", 0.5)),
            processing_time_ms=round(latency, 2),
            atlas_techniques=["AML.T0051"] if score > 40 else [],
            metadata={
                "is_injection": data.get("is_injection", False),
                "model_source": settings.local_model_name,
                "air_gap_mode": True,
            },
        )

    except ImportError:
        return LayerResult(
            layer=DetectionLayer.SEMANTIC_CLASSIFIER,
            threat_score=0.0,
            reasoning="Ollama not installed — pip install ollama",
            confidence=0.0,
            processing_time_ms=(time.time() - start) * 1000,
            metadata={"air_gap_mode": False, "error": "ollama_not_installed"},
        )
    except Exception as e:
        return LayerResult(
            layer=DetectionLayer.SEMANTIC_CLASSIFIER,
            threat_score=0.0,
            reasoning=f"Local model error: {e}",
            confidence=0.0,
            processing_time_ms=(time.time() - start) * 1000,
            metadata={"air_gap_mode": True, "error": str(e)},
        )
