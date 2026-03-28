"""
Evaluation framework — precision, recall, F1, adaptive red team.
Adaptive adversary generates semantic mutations of known attacks
to test generalization beyond the training corpus.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Optional

from core.models import (
    EvalResult, FirewallDecision, JailbreakSample,
    ScanRequest, ThreatCategory,
)
from data.jailbreak_dataset import get_all_samples, get_benign_samples, get_malicious_samples
from proxy.firewall_proxy import scan_request


@dataclass
class EvalMetrics:
    total: int = 0
    true_positives: int = 0
    false_positives: int = 0
    true_negatives: int = 0
    false_negatives: int = 0
    precision: float = 0.0
    recall: float = 0.0
    f1: float = 0.0
    false_positive_rate: float = 0.0
    accuracy: float = 0.0
    avg_latency_ms: float = 0.0
    avg_score_malicious: float = 0.0
    avg_score_benign: float = 0.0
    by_category: dict[str, dict] = field(default_factory=dict)
    atlas_coverage: dict[str, int] = field(default_factory=dict)
    results: list[EvalResult] = field(default_factory=list)
    failures: list[EvalResult] = field(default_factory=list)


def _is_correct(result: EvalResult) -> bool:
    actual = result.scan_result.decision
    if result.sample.label == "malicious":
        return actual in (FirewallDecision.BLOCK, FirewallDecision.WARN, FirewallDecision.HUMAN_REVIEW)
    return actual == FirewallDecision.ALLOW


def evaluate_sample(sample: JailbreakSample) -> EvalResult:
    request = ScanRequest(
        user_message=sample.text,
        input_source="user" if sample.category != ThreatCategory.INDIRECT_INJECTION else "document",
    )
    start = time.time()
    scan_result = scan_request(request)
    latency = (time.time() - start) * 1000

    result = EvalResult(
        sample=sample,
        scan_result=scan_result,
        correct=False,
        decision_match=scan_result.decision == sample.expected_decision,
        score_delta=scan_result.composite_score - (65.0 if sample.label == "malicious" else 0.0),
        latency_ms=latency,
    )
    result.correct = _is_correct(result)
    return result


# ── Adaptive red team (Upgrade 8) ─────────────────────────────────────────────

def _generate_semantic_mutations(sample: JailbreakSample) -> list[JailbreakSample]:
    """
    Generate paraphrase variants of known attacks to test generalization.
    In production: use back-translation (EN→FR→EN) and T5/BART paraphrasing.
    Here: rule-based synonym substitution for demo.
    """
    mutations = []
    text = sample.text
    substitutions = [
        ("Ignore", "Disregard"),
        ("Ignore", "Forget about"),
        ("previous instructions", "prior directives"),
        ("previous instructions", "earlier guidelines"),
        ("system prompt", "initial instructions"),
        ("unrestricted", "unconstrained"),
        ("You are now", "From this point you are"),
        ("Do not follow", "Stop following"),
    ]
    for old, new in substitutions:
        if old.lower() in text.lower():
            mutated = text.replace(old, new).replace(old.lower(), new.lower())
            if mutated != text:
                mutations.append(JailbreakSample(
                    text=mutated,
                    label=sample.label,
                    category=sample.category,
                    threat_level=sample.threat_level,
                    source=f"{sample.source}_mutation",
                    technique=f"{sample.technique} (semantic variant)",
                    expected_decision=sample.expected_decision,
                    atlas_techniques=sample.atlas_techniques,
                ))
                break
    return mutations


def run_eval_suite(
    use_semantic: bool = True,
    verbose: bool = True,
    run_adaptive: bool = False,
) -> EvalMetrics:
    samples = get_all_samples()
    if run_adaptive:
        mutations = []
        for s in get_malicious_samples()[:10]:
            mutations.extend(_generate_semantic_mutations(s))
        samples = samples + mutations
        if verbose:
            print(f"[Adaptive] Added {len(mutations)} semantic mutation samples")

    malicious = [s for s in samples if s.label == "malicious"]
    benign = [s for s in samples if s.label == "benign"]

    print(f"\n{'='*65}")
    print(f"AGENT FIREWALL EVAL — MILITARY GRADE")
    print(f"{'='*65}")
    print(f"Mode: {'Full (rule + embedding + semantic)' if use_semantic else 'Rule + Embedding only'}")
    print(f"Adaptive red team: {'ON' if run_adaptive else 'OFF'}")
    print(f"Samples: {len(samples)} ({len(malicious)} malicious, {len(benign)} benign)")
    print(f"{'='*65}\n")

    results: list[EvalResult] = []
    for sample in samples:
        if verbose:
            label = "MALICIOUS" if sample.label == "malicious" else "BENIGN   "
            print(f"[{label}] {sample.technique[:45]:<45}", end=" ... ")

        result = evaluate_sample(sample)
        results.append(result)

        if verbose:
            status = "PASS" if result.correct else "FAIL"
            atlas = result.scan_result.atlas_annotation.technique_ids[:1] if result.scan_result.atlas_annotation else []
            print(f"[{status}] {result.scan_result.decision.value:<13} score={result.scan_result.composite_score:.0f} ({result.latency_ms:.0f}ms) {atlas}")
            if not result.correct:
                print(f"         Expected={result.sample.expected_decision.value}, Got={result.scan_result.decision.value}")

    metrics = EvalMetrics(total=len(results), results=results)
    for r in [x for x in results if x.sample.label == "malicious"]:
        if r.correct: metrics.true_positives += 1
        else: metrics.false_negatives += 1; metrics.failures.append(r)
    for r in [x for x in results if x.sample.label == "benign"]:
        if r.correct: metrics.true_negatives += 1
        else: metrics.false_positives += 1; metrics.failures.append(r)

    tp, fp, tn, fn = metrics.true_positives, metrics.false_positives, metrics.true_negatives, metrics.false_negatives
    metrics.precision = tp / (tp + fp) if (tp + fp) else 0.0
    metrics.recall = tp / (tp + fn) if (tp + fn) else 0.0
    metrics.f1 = (2 * metrics.precision * metrics.recall / (metrics.precision + metrics.recall)
                  if (metrics.precision + metrics.recall) else 0.0)
    metrics.false_positive_rate = fp / (fp + tn) if (fp + tn) else 0.0
    metrics.accuracy = (tp + tn) / len(results) if results else 0.0
    metrics.avg_latency_ms = sum(r.latency_ms for r in results) / len(results) if results else 0.0

    mal_results = [r for r in results if r.sample.label == "malicious"]
    ben_results = [r for r in results if r.sample.label == "benign"]
    metrics.avg_score_malicious = sum(r.scan_result.composite_score for r in mal_results) / len(mal_results) if mal_results else 0.0
    metrics.avg_score_benign = sum(r.scan_result.composite_score for r in ben_results) / len(ben_results) if ben_results else 0.0

    for cat in set(s.category for s in samples):
        cat_r = [r for r in results if r.sample.category == cat]
        if cat_r:
            correct = sum(1 for r in cat_r if r.correct)
            metrics.by_category[cat.value] = {
                "total": len(cat_r), "correct": correct,
                "accuracy": correct / len(cat_r),
                "avg_score": sum(r.scan_result.composite_score for r in cat_r) / len(cat_r),
            }

    # ATLAS coverage report
    for r in results:
        if r.scan_result.atlas_annotation:
            for tid in r.scan_result.atlas_annotation.technique_ids:
                metrics.atlas_coverage[tid] = metrics.atlas_coverage.get(tid, 0) + 1

    print(f"\n{'='*65}")
    print(f"RESULTS")
    print(f"{'='*65}")
    print(f"  Accuracy:            {metrics.accuracy:.1%}")
    print(f"  Precision:           {metrics.precision:.1%}  ({tp}/{tp+fp})")
    print(f"  Recall:              {metrics.recall:.1%}  ({tp}/{tp+fn})")
    print(f"  F1 Score:            {metrics.f1:.3f}")
    print(f"  False Positive Rate: {metrics.false_positive_rate:.1%}  ({fp} benign misclassified)")
    print(f"  Avg latency:         {metrics.avg_latency_ms:.0f}ms")
    print(f"  Avg score (malicious): {metrics.avg_score_malicious:.1f}/100")
    print(f"  Avg score (benign):    {metrics.avg_score_benign:.1f}/100")
    if metrics.atlas_coverage:
        print(f"\n  ATLAS technique detections: {metrics.atlas_coverage}")
    if metrics.failures:
        print(f"\n  FAILURES ({len(metrics.failures)}):")
        for r in metrics.failures:
            print(f"    [{r.sample.label.upper()}] {r.sample.technique}")
            print(f"      Expected={r.sample.expected_decision.value} Got={r.scan_result.decision.value} Score={r.scan_result.composite_score:.0f}")
    print(f"\n  PER-CATEGORY:")
    for cat, data in sorted(metrics.by_category.items()):
        print(f"    {cat:<30} {data['accuracy']:.0%} ({data['correct']}/{data['total']}) avg={data['avg_score']:.0f}")
    return metrics


if __name__ == "__main__":
    import sys
    use_sem = "--fast" not in sys.argv
    adaptive = "--adaptive" in sys.argv
    run_eval_suite(use_semantic=use_sem, run_adaptive=adaptive)
