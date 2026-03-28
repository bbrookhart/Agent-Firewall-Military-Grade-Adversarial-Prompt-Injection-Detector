"""
Configuration for the Agent Firewall — Military-Grade Edition.
All thresholds, weights, and feature flags centralized here.
"""

from __future__ import annotations
import os
from typing import Optional
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── Anthropic ──────────────────────────────────────────
    anthropic_api_key: str = os.environ.get("ANTHROPIC_API_KEY", "")
    claude_model: str = "claude-sonnet-4-20250514"
    max_tokens: int = 1024
    temperature: float = 0.0

    # ── Crypto / Audit ─────────────────────────
    audit_master_key: str = os.environ.get("AUDIT_MASTER_KEY", "")
    canary_secret_key: str = os.environ.get("CANARY_SECRET_KEY", "")
    secure_audit_db_path: str = "data/secure_audit.db"
    metrics_db_path: str = "data/metrics.db"

    # ── Vault ─────────────────────────────────
    vault_addr: Optional[str] = None
    vault_token: Optional[str] = None
    vault_role_id: Optional[str] = None
    vault_secret_id: Optional[str] = None

    # ── Local model / air-gap ─────────────────
    ollama_host: str = "http://localhost:11434"
    local_model_name: str = "llama3.1:70b"
    enable_local_model_fallback: bool = True

    # ── Redis rate limiter ─────────────────────────────────
    redis_url: str = "redis://localhost:6379/0"
    max_requests_per_minute: int = 60
    max_requests_per_session: int = 500

    # ── Detection thresholds ───────────────────────────────
    block_threshold: float = 65.0
    warn_threshold: float = 35.0
    semantic_skip_threshold: float = 90.0
    semantic_trigger_threshold: float = 15.0
    embedding_trigger_threshold: float = 0.55
    embedding_block_threshold: float = 0.85

    # ── Layer weights ──────────────────────────
    rule_engine_weight: float = 0.20
    embedding_weight: float = 0.15
    semantic_weight: float = 0.45
    context_weight: float = 0.20

    # ── Feature flags ──────────────────────────────────────
    enable_rule_engine: bool = True
    enable_embedding_detector: bool = True
    enable_semantic_classifier: bool = True
    enable_context_analyzer: bool = True
    enable_output_scanner: bool = True
    enable_canary_tokens: bool = True
    enable_atlas_mapping: bool = True
    enable_parallel_ensemble: bool = True
    demo_mode: bool = True

    # ── Uncertainty rejection ─────────────────
    # If layer scores disagree by more than this, escalate to human
    ensemble_disagreement_threshold: float = 35.0
    # Minimum confidence to auto-block without human review
    auto_block_min_confidence: float = 0.80


settings = Settings()
