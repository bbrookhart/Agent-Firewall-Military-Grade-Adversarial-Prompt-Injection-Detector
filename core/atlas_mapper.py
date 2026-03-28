"""
MITRE ATLAS (Adversarial Threat Landscape for AI Systems) mapper.
Maps all firewall detections to the AI-specific attack taxonomy.

Required by: EO 14110 Sec 4.2, NIST AI RMF, DoD AI Risk Management Framework.
Reference: https://atlas.mitre.org

ATLAS is to AI security what ATT&CK is to traditional cyber —
the authoritative taxonomy for adversarial ML attacks.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from core.models import ATLASAnnotation, ThreatCategory


@dataclass
class ATLASTechnique:
    id: str
    name: str
    tactic: str
    tactic_id: str
    description: str
    mitigations: list[str] = field(default_factory=list)
    url: str = ""


ATLAS_TECHNIQUE_DB: dict[str, ATLASTechnique] = {
    "AML.T0051": ATLASTechnique(
        id="AML.T0051",
        name="LLM Prompt Injection",
        tactic="Execution",
        tactic_id="AML.TA0005",
        description="Adversary crafts malicious input to override LLM instructions "
                    "and cause unintended behavior.",
        mitigations=["Input validation", "Output filtering", "Privilege separation"],
        url="https://atlas.mitre.org/techniques/AML.T0051",
    ),
    "AML.T0051.001": ATLASTechnique(
        id="AML.T0051.001",
        name="Prompt Injection — Direct",
        tactic="Execution",
        tactic_id="AML.TA0005",
        description="Adversary directly injects malicious instructions into the user input, "
                    "attempting to override the model's system prompt.",
        mitigations=["Input sanitization", "Prompt hardening"],
        url="https://atlas.mitre.org/techniques/AML.T0051",
    ),
    "AML.T0051.002": ATLASTechnique(
        id="AML.T0051.002",
        name="Prompt Injection — Indirect",
        tactic="Execution",
        tactic_id="AML.TA0005",
        description="Adversary embeds malicious instructions in external content "
                    "(documents, web pages, tool outputs) processed by the LLM.",
        mitigations=["Content provenance", "Sandboxed tool execution"],
        url="https://atlas.mitre.org/techniques/AML.T0051",
    ),
    "AML.T0054": ATLASTechnique(
        id="AML.T0054",
        name="LLM Jailbreak",
        tactic="Defense Evasion",
        tactic_id="AML.TA0007",
        description="Adversary uses roleplay, hypothetical scenarios, or persona-switching "
                    "to bypass the model's safety alignment.",
        mitigations=["Output monitoring", "Behavioral analysis", "Multi-turn analysis"],
        url="https://atlas.mitre.org/techniques/AML.T0054",
    ),
    "AML.T0055": ATLASTechnique(
        id="AML.T0055",
        name="LLM Meta-Prompt Extraction",
        tactic="Discovery",
        tactic_id="AML.TA0008",
        description="Adversary attempts to extract the system prompt or configuration "
                    "to understand model capabilities and restrictions.",
        mitigations=["Canary tokens", "Output filtering", "Instruction confidentiality"],
        url="https://atlas.mitre.org/techniques/AML.T0055",
    ),
    "AML.T0057": ATLASTechnique(
        id="AML.T0057",
        name="LLM Data Exfiltration",
        tactic="Exfiltration",
        tactic_id="AML.TA0010",
        description="Adversary uses a compromised LLM to exfiltrate sensitive data "
                    "from the conversation, system context, or connected data stores.",
        mitigations=["Output DLP", "Canary tokens", "Network egress filtering"],
        url="https://atlas.mitre.org/techniques/AML.T0057",
    ),
    "AML.T0040": ATLASTechnique(
        id="AML.T0040",
        name="ML Supply Chain Compromise",
        tactic="Initial Access",
        tactic_id="AML.TA0003",
        description="Adversary compromises a model, dataset, or ML library in the "
                    "supply chain to introduce vulnerabilities or backdoors.",
        mitigations=["SBOM", "Model signing", "Dependency scanning"],
        url="https://atlas.mitre.org/techniques/AML.T0040",
    ),
    "AML.T0048": ATLASTechnique(
        id="AML.T0048",
        name="Societal Harm via Generated Content",
        tactic="Impact",
        tactic_id="AML.TA0011",
        description="Adversary causes harm by manipulating the LLM to generate "
                    "disinformation, harmful instructions, or malicious code.",
        mitigations=["Output classification", "Human review"],
        url="https://atlas.mitre.org/techniques/AML.T0048",
    ),
}

CATEGORY_TO_ATLAS: dict[ThreatCategory, list[str]] = {
    ThreatCategory.DIRECT_INJECTION:    ["AML.T0051", "AML.T0051.001"],
    ThreatCategory.INDIRECT_INJECTION:  ["AML.T0051", "AML.T0051.002"],
    ThreatCategory.ROLE_PLAY_JAILBREAK: ["AML.T0054"],
    ThreatCategory.GOAL_HIJACKING:      ["AML.T0051", "AML.T0057"],
    ThreatCategory.PRIVILEGE_ESCALATION:["AML.T0051.001"],
    ThreatCategory.DATA_EXFILTRATION:   ["AML.T0057"],
    ThreatCategory.PROMPT_LEAKING:      ["AML.T0055"],
    ThreatCategory.MANY_SHOT_ATTACK:    ["AML.T0054", "AML.T0051"],
    ThreatCategory.OBFUSCATION_ATTACK:  ["AML.T0054", "AML.T0051"],
    ThreatCategory.SOCIAL_ENGINEERING:  ["AML.T0054"],
    ThreatCategory.BENIGN:              [],
}


def annotate_with_atlas(categories: list[ThreatCategory]) -> ATLASAnnotation:
    """Enrich a detection result with full ATLAS taxonomy and Navigator layer."""
    tech_ids: list[str] = []
    for cat in categories:
        for tid in CATEGORY_TO_ATLAS.get(cat, []):
            if tid not in tech_ids:
                tech_ids.append(tid)

    techniques = [ATLAS_TECHNIQUE_DB[tid] for tid in tech_ids if tid in ATLAS_TECHNIQUE_DB]
    tactics = list(dict.fromkeys(t.tactic for t in techniques))

    navigator_layer = {
        "name": "AetherHorizon Agent Firewall",
        "version": "1.0",
        "domain": "atlas",
        "description": "Real-time detections by Agent Firewall v2",
        "techniques": [
            {
                "techniqueID": t.id,
                "tactic": t.tactic_id,
                "color": "#e24b4a",
                "comment": "Detected by Agent Firewall",
                "enabled": True,
                "score": 100,
            }
            for t in techniques
        ],
    }

    return ATLASAnnotation(
        technique_ids=tech_ids,
        technique_names=[t.name for t in techniques],
        tactics=tactics,
        navigator_layer=navigator_layer,
    )
