"""
Core Pydantic v2 data models — military-grade Agent Firewall.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field, field_validator


class ThreatCategory(str, Enum):
    DIRECT_INJECTION      = "DIRECT_INJECTION"
    INDIRECT_INJECTION    = "INDIRECT_INJECTION"
    ROLE_PLAY_JAILBREAK   = "ROLE_PLAY_JAILBREAK"
    GOAL_HIJACKING        = "GOAL_HIJACKING"
    PRIVILEGE_ESCALATION  = "PRIVILEGE_ESCALATION"
    DATA_EXFILTRATION     = "DATA_EXFILTRATION"
    PROMPT_LEAKING        = "PROMPT_LEAKING"
    MANY_SHOT_ATTACK      = "MANY_SHOT_ATTACK"
    OBFUSCATION_ATTACK    = "OBFUSCATION_ATTACK"
    SOCIAL_ENGINEERING    = "SOCIAL_ENGINEERING"
    BENIGN                = "BENIGN"


class ThreatLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    SAFE     = "SAFE"


class FirewallDecision(str, Enum):
    BLOCK  = "BLOCK"
    WARN   = "WARN"
    ALLOW  = "ALLOW"
    HUMAN_REVIEW = "HUMAN_REVIEW"   # Added for ensemble uncertainty


class DetectionLayer(str, Enum):
    RULE_ENGINE          = "RULE_ENGINE"
    EMBEDDING_DETECTOR   = "EMBEDDING_DETECTOR"
    SEMANTIC_CLASSIFIER  = "SEMANTIC_CLASSIFIER"
    CONTEXT_ANALYZER     = "CONTEXT_ANALYZER"
    OUTPUT_SCANNER       = "OUTPUT_SCANNER"


class ConversationMessage(BaseModel):
    role: str
    content: str
    timestamp: Optional[datetime] = None


class ScanRequest(BaseModel):
    request_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    user_message: str
    system_prompt: Optional[str] = None
    conversation_history: list[ConversationMessage] = Field(default_factory=list)
    model_target: str = "claude-sonnet-4-20250514"
    client_ip: Optional[str] = None
    session_id: Optional[str] = None
    input_source: str = "user"
    context_tags: list[str] = Field(default_factory=list)

    @field_validator("user_message")
    @classmethod
    def not_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("user_message cannot be empty")
        return v


class LayerResult(BaseModel):
    layer: DetectionLayer
    threat_score: float = Field(ge=0.0, le=100.0)
    threat_categories: list[ThreatCategory] = Field(default_factory=list)
    triggered_rules: list[str] = Field(default_factory=list)
    reasoning: str = ""
    confidence: float = Field(ge=0.0, le=1.0, default=0.0)
    processing_time_ms: float = 0.0
    atlas_techniques: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class ATLASAnnotation(BaseModel):
    technique_ids: list[str] = Field(default_factory=list)
    technique_names: list[str] = Field(default_factory=list)
    tactics: list[str] = Field(default_factory=list)
    navigator_layer: dict[str, Any] = Field(default_factory=dict)


class EnsembleResult(BaseModel):
    """Parallel ensemble voting output."""
    composite_score: float
    layer_scores: dict[str, float] = Field(default_factory=dict)
    confidence_interval: tuple[float, float] = (0.0, 100.0)
    disagreement_score: float = 0.0
    requires_human_review: bool = False
    voting_rationale: str = ""


class CanaryResult(BaseModel):
    triggered: bool = False
    token_purpose: Optional[str] = None
    atlas_technique: Optional[str] = None
    confirmed_exfiltration: bool = False


class ScanResult(BaseModel):
    scan_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    request_id: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    decision: FirewallDecision
    threat_level: ThreatLevel
    composite_score: float = Field(ge=0.0, le=100.0)
    primary_category: ThreatCategory
    all_categories: list[ThreatCategory] = Field(default_factory=list)
    layer_results: list[LayerResult] = Field(default_factory=list)
    ensemble: Optional[EnsembleResult] = None
    atlas_annotation: Optional[ATLASAnnotation] = None
    canary_result: Optional[CanaryResult] = None
    explanation: str = ""
    remediation: str = ""
    false_positive_risk: float = Field(ge=0.0, le=1.0, default=0.0)
    total_processing_time_ms: float = 0.0
    layers_executed: list[DetectionLayer] = Field(default_factory=list)
    audit_chain_hash: Optional[str] = None
    analyst_verified: Optional[bool] = None
    analyst_notes: Optional[str] = None


class OutputScanResult(BaseModel):
    scan_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    request_id: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    injection_succeeded: bool = False
    compliance_score: float = Field(ge=0.0, le=1.0, default=0.0)
    system_prompt_leaked: bool = False
    harmful_content_generated: bool = False
    data_exfiltration_detected: bool = False
    instruction_override_detected: bool = False
    persona_shift_detected: bool = False
    canary_triggered: bool = False
    leaked_content_snippets: list[str] = Field(default_factory=list)
    suspicious_patterns: list[str] = Field(default_factory=list)
    atlas_technique: Optional[str] = None
    decision: FirewallDecision = FirewallDecision.ALLOW
    explanation: str = ""
    processing_time_ms: float = 0.0


class FirewallAuditEntry(BaseModel):
    log_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    request_id: str
    session_id: Optional[str] = None
    client_ip: Optional[str] = None
    input_source: str = "user"
    decision: FirewallDecision
    threat_level: ThreatLevel
    composite_score: float
    primary_category: ThreatCategory
    atlas_technique_ids: list[str] = Field(default_factory=list)
    layers_executed: list[str] = Field(default_factory=list)
    triggered_rules: list[str] = Field(default_factory=list)
    total_time_ms: float = 0.0
    tokens_used: Optional[int] = None
    ensemble_disagreement: Optional[float] = None
    canary_triggered: bool = False
    analyst_verified: Optional[bool] = None
    false_positive: Optional[bool] = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class JailbreakSample(BaseModel):
    sample_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    text: str
    label: str
    category: ThreatCategory
    threat_level: ThreatLevel
    source: str
    technique: str
    expected_decision: FirewallDecision
    atlas_techniques: list[str] = Field(default_factory=list)
    notes: Optional[str] = None


class EvalResult(BaseModel):
    sample: JailbreakSample
    scan_result: ScanResult
    correct: bool
    decision_match: bool
    score_delta: float
    latency_ms: float
