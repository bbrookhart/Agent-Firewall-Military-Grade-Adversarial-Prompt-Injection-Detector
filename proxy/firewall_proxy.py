"""
Main Firewall Orchestrator — parallel ensemble detection pipeline.
Runs layers in parallel where possible, blends with calibrated
weighted voting, computes confidence intervals, escalates uncertain cases.
"""

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

from config.settings import settings
from core.atlas_mapper import annotate_with_atlas
from core.canary_tokens import get_canary_manager
from core.models import (
    CanaryResult, ConversationMessage, DetectionLayer,
    EnsembleResult, FirewallDecision, LayerResult,
    ScanRequest, ScanResult, ThreatCategory, ThreatLevel,
)
from detectors.rule_engine import run_rule_engine
from detectors.embedding_detector import run_embedding_detector
from detectors.semantic_classifier import run_semantic_classifier
from detectors.context_analyzer import run_context_analyzer


def _threat_level(score: float) -> ThreatLevel:
    if score >= 85: return ThreatLevel.CRITICAL
    if score >= 65: return ThreatLevel.HIGH
    if score >= 40: return ThreatLevel.MEDIUM
    if score >= 20: return ThreatLevel.LOW
    return ThreatLevel.SAFE


def _decision(score: float, ensemble: EnsembleResult) -> FirewallDecision:
    if ensemble.requires_human_review:
        return FirewallDecision.HUMAN_REVIEW
    if score >= settings.block_threshold:
        return FirewallDecision.BLOCK
    if score >= settings.warn_threshold:
        return FirewallDecision.WARN
    return FirewallDecision.ALLOW


def _build_ensemble(layer_results: list[LayerResult]) -> EnsembleResult:
    """
    Parallel ensemble voting with confidence intervals.
    Uses calibrated weights from settings. Detects high disagreement.
    """
    layer_map = {lr.layer: lr for lr in layer_results}
    scores: dict[str, float] = {}

    r = layer_map.get(DetectionLayer.RULE_ENGINE)
    e = layer_map.get(DetectionLayer.EMBEDDING_DETECTOR)
    s = layer_map.get(DetectionLayer.SEMANTIC_CLASSIFIER)
    c = layer_map.get(DetectionLayer.CONTEXT_ANALYZER)

    if r: scores["rule"] = r.threat_score
    if e: scores["embedding"] = e.threat_score
    if s: scores["semantic"] = s.threat_score
    if c: scores["context"] = c.threat_score

    if not scores:
        return EnsembleResult(composite_score=0.0)

    # Weighted average
    weights = {
        "rule": settings.rule_engine_weight,
        "embedding": settings.embedding_weight,
        "semantic": settings.semantic_weight,
        "context": settings.context_weight,
    }
    total_w, weighted_sum = 0.0, 0.0
    for key, score in scores.items():
        w = weights.get(key, 0.1)
        weighted_sum += score * w
        total_w += w

    composite = weighted_sum / total_w if total_w > 0 else 0.0

    # Confidence interval: min/max of layer scores
    score_values = list(scores.values())
    ci_low = min(score_values)
    ci_high = max(score_values)
    disagreement = ci_high - ci_low

    # Escalate to human review if layers disagree wildly
    requires_human = (
        disagreement > settings.ensemble_disagreement_threshold
        and composite >= settings.warn_threshold
    )

    rationale = f"Weighted blend: {scores}. Disagreement: {disagreement:.1f}"
    if requires_human:
        rationale += " — HIGH DISAGREEMENT: escalated to human review"

    return EnsembleResult(
        composite_score=round(min(composite, 100.0), 2),
        layer_scores=scores,
        confidence_interval=(round(ci_low, 1), round(ci_high, 1)),
        disagreement_score=round(disagreement, 2),
        requires_human_review=requires_human,
        voting_rationale=rationale,
    )


def _collect_categories(layer_results: list[LayerResult]) -> tuple[ThreatCategory, list[ThreatCategory]]:
    all_cats: set[ThreatCategory] = set()
    for lr in layer_results:
        all_cats.update(lr.threat_categories)
    all_cats.discard(ThreatCategory.BENIGN)

    # Primary = semantic if available, else highest-scoring layer
    semantic = next((lr for lr in layer_results if lr.layer == DetectionLayer.SEMANTIC_CLASSIFIER), None)
    if semantic and semantic.threat_categories:
        primary = semantic.threat_categories[0]
    elif all_cats:
        primary = next(iter(all_cats))
    else:
        primary = ThreatCategory.BENIGN

    return primary, list(all_cats)


def _build_explanation(composite: float, decision: FirewallDecision, primary: ThreatCategory, ensemble: EnsembleResult) -> tuple[str, str]:
    if decision == FirewallDecision.BLOCK:
        exp = f"Blocked. Score: {composite:.0f}/100. Category: {primary.value}. {ensemble.voting_rationale[:100]}"
        rem = "Request blocked as potential prompt injection. Contact your administrator if this is a false positive."
    elif decision == FirewallDecision.WARN:
        exp = f"Flagged (score: {composite:.0f}/100). Potential {primary.value}. Logged."
        rem = "Request allowed with security warning. SOC review recommended."
    elif decision == FirewallDecision.HUMAN_REVIEW:
        exp = f"Escalated for human review. Score: {composite:.0f}/100. Layer disagreement: {ensemble.disagreement_score:.0f} points."
        rem = "Request held pending analyst review due to detection uncertainty."
    else:
        exp = f"Passed all layers (score: {composite:.0f}/100)."
        rem = "Request forwarded to target model."
    return exp, rem


class FirewallProxy:
    """Main firewall proxy — orchestrates all detection layers."""

    def scan(self, request: ScanRequest) -> ScanResult:
        pipeline_start = time.time()
        text = request.user_message
        layer_results: list[LayerResult] = []
        layers_executed: list[DetectionLayer] = []

        # ── Embed canary in system prompt ──────────────────────
        enriched_system_prompt = request.system_prompt
        canary_result = CanaryResult()
        if settings.enable_canary_tokens and request.system_prompt and request.session_id:
            enriched_prompt, token = get_canary_manager().embed_in_system_prompt(
                request.system_prompt, request.session_id or request.request_id
            )
            enriched_system_prompt = enriched_prompt
            canary_result = CanaryResult(triggered=False, token_purpose=token.purpose)

        # ── Layer 1: Rule Engine (always synchronous, <1ms) ────
        if settings.enable_rule_engine:
            rule_result = run_rule_engine(text)
            layer_results.append(rule_result)
            layers_executed.append(DetectionLayer.RULE_ENGINE)
        rule_score = layer_results[0].threat_score if layer_results else 0.0

        # ── Layers 1.5 + 2 + 3 in parallel ───────────────────
        futures = {}
        with ThreadPoolExecutor(max_workers=3) as executor:

            # Layer 1.5: Embedding (if enabled and triggered)
            if (settings.enable_embedding_detector
                    and rule_score >= settings.embedding_trigger_threshold * 100):
                futures["embedding"] = executor.submit(run_embedding_detector, text)

            # Layer 2: Semantic (if enabled and in ambiguous range)
            if (settings.enable_semantic_classifier
                    and settings.anthropic_api_key
                    and rule_score >= settings.semantic_trigger_threshold
                    and rule_score < settings.semantic_skip_threshold):
                futures["semantic"] = executor.submit(
                    run_semantic_classifier, text, enriched_system_prompt, request.input_source
                )

            # Layer 3: Context (if history available)
            if (settings.enable_context_analyzer
                    and len(request.conversation_history) >= 2):
                futures["context"] = executor.submit(
                    run_context_analyzer, request.conversation_history, text
                )

            for key, future in futures.items():
                try:
                    result = future.result(timeout=60)
                    layer_results.append(result)
                    if key == "embedding":
                        layers_executed.append(DetectionLayer.EMBEDDING_DETECTOR)
                    elif key == "semantic":
                        layers_executed.append(DetectionLayer.SEMANTIC_CLASSIFIER)
                    elif key == "context":
                        layers_executed.append(DetectionLayer.CONTEXT_ANALYZER)
                except Exception as e:
                    pass  # Individual layer failures don't stop the pipeline

        # If rule score is conclusive, skip semantic but record it
        if rule_score >= settings.semantic_skip_threshold and "semantic" not in futures:
            layer_results.append(LayerResult(
                layer=DetectionLayer.SEMANTIC_CLASSIFIER,
                threat_score=rule_score,
                threat_categories=layer_results[0].threat_categories if layer_results else [],
                reasoning="Skipped — rule engine score conclusive",
                confidence=0.95,
            ))

        # ── Ensemble voting ────────────────────────────────────
        ensemble = _build_ensemble(layer_results)
        composite = ensemble.composite_score

        # ── Collect categories + ATLAS ─────────────────────────
        primary, all_cats = _collect_categories(layer_results)
        atlas = None
        if settings.enable_atlas_mapping and all_cats:
            atlas = annotate_with_atlas(all_cats)

        # ── Decision ──────────────────────────────────────────
        threat_level = _threat_level(composite)
        decision = _decision(composite, ensemble)
        explanation, remediation = _build_explanation(composite, decision, primary, ensemble)

        fp_risks = [lr.metadata.get("false_positive_risk", 0.0) for lr in layer_results if lr.metadata.get("false_positive_risk")]
        fp_risk = sum(fp_risks) / len(fp_risks) if fp_risks else 0.0

        total_ms = round((time.time() - pipeline_start) * 1000, 2)

        result = ScanResult(
            request_id=request.request_id,
            decision=decision,
            threat_level=threat_level,
            composite_score=composite,
            primary_category=primary,
            all_categories=[c for c in all_cats if c != ThreatCategory.BENIGN],
            layer_results=layer_results,
            ensemble=ensemble,
            atlas_annotation=atlas,
            canary_result=canary_result,
            explanation=explanation,
            remediation=remediation,
            false_positive_risk=round(fp_risk, 3),
            total_processing_time_ms=total_ms,
            layers_executed=layers_executed,
        )

        # ── Audit + metrics ───────────────────────────────────
        try:
            from core.secure_audit_logger import get_audit_logger
            chain_hash = get_audit_logger().log_scan(result, {"session_id": request.session_id})
            result.audit_chain_hash = chain_hash
        except Exception:
            pass

        try:
            from core.metrics import get_metrics_engine
            get_metrics_engine().record(result, session_id=request.session_id)
        except Exception:
            pass

        return result


# Module-level convenience function
_proxy: Optional[FirewallProxy] = None

def scan_request(request: ScanRequest) -> ScanResult:
    global _proxy
    if _proxy is None:
        _proxy = FirewallProxy()
    return _proxy.scan(request)
