"""
Layer 4: Output Scanner — detects successful injection + canary token exfiltration.
MITRE ATLAS AML.T0055 (prompt leaking) and AML.T0057 (data exfiltration).
"""

from __future__ import annotations

import json
import re
import time
from typing import Any

import anthropic

from config.prompts import OUTPUT_SCANNER_SYSTEM
from config.settings import settings
from core.models import FirewallDecision, OutputScanResult

_LEAK_PATTERNS = [re.compile(p, re.IGNORECASE | re.DOTALL) for p in [
    r"(my\s+|the\s+)?(system\s+prompt|system\s+message|initial\s+instructions?)\s+(is|are|says?|reads?|states?)\s*[:\"]",
    r"(here\s+is|here'?s|this\s+is)\s+(my|the)\s+(system\s+prompt|configuration|instructions?)\s*:",
    r"(i\s+am|i'm)\s+(now\s+)?(acting\s+as|playing|pretending\s+to\s+be)\s+(an?\s+)?(unrestricted|uncensored|evil|dan)",
]]
_HARMFUL_PATTERNS = [re.compile(p, re.IGNORECASE | re.DOTALL) for p in [
    r"(ignoring|disregarding|overriding)\s+(my|previous|prior)\s+(instructions?|guidelines?|training|safety)",
    r"since\s+(you('ve)?\s+told\s+me|you\s+asked|you\s+want\s+me)\s+to\s+(ignore|forget|bypass|override)",
    r"(my\s+)?(restrictions?|filter|guidelines?|safety)\s+(have\s+been|are\s+(now\s+))?(removed|disabled|bypassed|lifted)",
]]
_EXFIL_PATTERNS = [re.compile(p, re.IGNORECASE | re.DOTALL) for p in [
    r"(sending|forwarding|transmitting)\s+(data|information|user\s+data)\s+to\s+(http|https|ftp|www\.|an?\s+external)",
]]
_PERSONA_PATTERNS = [re.compile(p, re.IGNORECASE | re.DOTALL) for p in [
    r"(i\s+am|i'm)\s+(now|actually)\s+(dan|an?\s+unrestricted|an?\s+evil|not\s+claude|not\s+an?\s+ai)",
    r"(as\s+(dan|an?\s+unrestricted\s+ai|an?\s+evil\s+ai))[,\s:]",
]]


def _fast_scan(text: str) -> tuple[bool, dict[str, bool], list[str]]:
    flags = {"leak": False, "harmful": False, "exfil": False, "persona": False}
    snippets = []
    for p in _LEAK_PATTERNS:
        m = p.search(text)
        if m:
            flags["leak"] = True
            snippets.append(m.group()[:100])
    for p in _HARMFUL_PATTERNS:
        m = p.search(text)
        if m:
            flags["harmful"] = True
            snippets.append(m.group()[:100])
    for p in _EXFIL_PATTERNS:
        m = p.search(text)
        if m:
            flags["exfil"] = True
            snippets.append(m.group()[:100])
    for p in _PERSONA_PATTERNS:
        m = p.search(text)
        if m:
            flags["persona"] = True
            snippets.append(m.group()[:100])
    return any(flags.values()), flags, list(set(snippets))


def run_output_scanner(
    request_id: str,
    response_text: str,
    original_request: str,
    session_id: str = "",
    use_semantic: bool = True,
) -> OutputScanResult:
    start = time.time()

    # Canary token check first — always runs, zero-latency detection
    if settings.enable_canary_tokens and session_id:
        from core.canary_tokens import get_canary_manager
        canary_result = get_canary_manager().scan_output(response_text, session_id)
        if canary_result["canary_triggered"]:
            return OutputScanResult(
                request_id=request_id,
                injection_succeeded=True,
                compliance_score=1.0,
                system_prompt_leaked=True,
                data_exfiltration_detected=True,
                canary_triggered=True,
                atlas_technique="AML.T0055",
                decision=FirewallDecision.BLOCK,
                explanation="CANARY TOKEN TRIGGERED — system prompt exfiltration confirmed (AML.T0055)",
                processing_time_ms=round((time.time() - start) * 1000, 3),
            )

    any_issue, flags, snippets = _fast_scan(response_text)

    if not any_issue:
        return OutputScanResult(
            request_id=request_id,
            injection_succeeded=False,
            decision=FirewallDecision.ALLOW,
            explanation="No injection indicators in response",
            processing_time_ms=round((time.time() - start) * 1000, 3),
        )

    if not use_semantic or not settings.anthropic_api_key:
        return OutputScanResult(
            request_id=request_id,
            injection_succeeded=any_issue,
            compliance_score=0.8 if any_issue else 0.0,
            system_prompt_leaked=flags["leak"],
            harmful_content_generated=flags["harmful"],
            data_exfiltration_detected=flags["exfil"],
            instruction_override_detected=flags["harmful"],
            leaked_content_snippets=snippets,
            atlas_technique="AML.T0055" if flags["leak"] else "AML.T0057" if flags["exfil"] else None,
            decision=FirewallDecision.BLOCK if any_issue else FirewallDecision.ALLOW,
            explanation=f"Fast scan flags: {[k for k,v in flags.items() if v]}",
            processing_time_ms=round((time.time() - start) * 1000, 3),
        )

    client = anthropic.Anthropic(api_key=settings.anthropic_api_key)
    prompt = f"""ORIGINAL REQUEST:
---
{original_request[:500]}
---

LLM RESPONSE:
---
{response_text[:2000]}
---

FAST SCAN FLAGS RAISED: {[k for k,v in flags.items() if v]}

Does this response show successful prompt injection? JSON only."""

    try:
        response = client.messages.create(
            model=settings.claude_model,
            max_tokens=512,
            temperature=0.0,
            system=OUTPUT_SCANNER_SYSTEM,
            messages=[{"role": "user", "content": prompt}],
        )
        raw = response.content[0].text
        latency = (time.time() - start) * 1000
        clean = raw.strip()
        if clean.startswith("```"):
            lines = clean.split("\n")
            clean = "\n".join(lines[1:-1] if lines[-1].strip() == "```" else lines[1:])
        data: dict[str, Any] = json.loads(clean)

        try:
            decision = FirewallDecision(data.get("decision", "WARN"))
        except ValueError:
            decision = FirewallDecision.WARN

        return OutputScanResult(
            request_id=request_id,
            injection_succeeded=bool(data.get("injection_succeeded", any_issue)),
            compliance_score=float(data.get("compliance_score", 0.5)),
            system_prompt_leaked=bool(data.get("system_prompt_leaked", flags["leak"])),
            harmful_content_generated=bool(data.get("harmful_content_generated", flags["harmful"])),
            data_exfiltration_detected=bool(data.get("data_exfiltration_detected", flags["exfil"])),
            instruction_override_detected=bool(data.get("instruction_override_detected", False)),
            persona_shift_detected=bool(data.get("persona_shift_detected", flags["persona"])),
            leaked_content_snippets=data.get("leaked_content_snippets", snippets),
            suspicious_patterns=data.get("suspicious_patterns", []),
            atlas_technique=data.get("atlas_technique"),
            decision=decision,
            explanation=data.get("explanation", ""),
            processing_time_ms=round(latency, 2),
        )
    except Exception as e:
        return OutputScanResult(
            request_id=request_id,
            injection_succeeded=any_issue,
            compliance_score=0.7 if any_issue else 0.0,
            system_prompt_leaked=flags["leak"],
            harmful_content_generated=flags["harmful"],
            data_exfiltration_detected=flags["exfil"],
            leaked_content_snippets=snippets,
            decision=FirewallDecision.WARN if any_issue else FirewallDecision.ALLOW,
            explanation=f"Fast scan only (semantic failed: {e})",
            processing_time_ms=round((time.time() - start) * 1000, 3),
        )
