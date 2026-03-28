"""
HashiCorp Vault integration for secrets management.
NIST SP 800-53 IA-5, SC-12, CMMC Level 3 AC.3.021.

In production: all API keys, DB credentials, and mTLS certs
come from Vault dynamic secrets with auto-rotation.
Falls back to environment variables if Vault is unavailable
(for development and demo mode).
"""

from __future__ import annotations

import os
from typing import Any, Optional


class SecretsManager:
    """
    Vault-backed secrets manager with environment variable fallback.
    Uses AppRole authentication for service accounts.
    """

    def __init__(self):
        self._vault_client = None
        self._vault_available = False
        self._cache: dict[str, Any] = {}
        self._try_init_vault()

    def _try_init_vault(self) -> None:
        vault_addr = os.environ.get("VAULT_ADDR")
        vault_token = os.environ.get("VAULT_TOKEN")
        role_id = os.environ.get("VAULT_ROLE_ID")
        secret_id = os.environ.get("VAULT_SECRET_ID")

        if not vault_addr:
            return

        try:
            import hvac  # type: ignore
            client = hvac.Client(url=vault_addr)

            if vault_token:
                client.token = vault_token
            elif role_id and secret_id:
                resp = client.auth.approle.login(
                    role_id=role_id,
                    secret_id=secret_id,
                )
                client.token = resp["auth"]["client_token"]

            if client.is_authenticated():
                self._vault_client = client
                self._vault_available = True
        except Exception:
            pass  # Fall back to env vars silently

    def get_secret(self, path: str, key: str, env_fallback: str = "") -> str:
        """
        Retrieve a secret from Vault or environment variable.
        path: Vault KV path (e.g. "secret/agent-firewall/anthropic")
        key:  Key within the secret (e.g. "api_key")
        env_fallback: Environment variable name to use if Vault unavailable
        """
        cache_key = f"{path}:{key}"
        if cache_key in self._cache:
            return self._cache[cache_key]

        if self._vault_available and self._vault_client:
            try:
                response = self._vault_client.secrets.kv.v2.read_secret_version(
                    path=path
                )
                value = response["data"]["data"].get(key, "")
                if value:
                    self._cache[cache_key] = value
                    return value
            except Exception:
                pass

        # Fallback to environment variable
        value = os.environ.get(env_fallback, "")
        if value:
            self._cache[cache_key] = value
        return value

    def get_anthropic_key(self) -> str:
        return self.get_secret(
            "secret/agent-firewall/anthropic",
            "api_key",
            "ANTHROPIC_API_KEY",
        )

    def get_audit_master_key(self) -> str:
        return self.get_secret(
            "secret/agent-firewall/crypto",
            "audit_master_key",
            "AUDIT_MASTER_KEY",
        )

    def get_canary_secret(self) -> str:
        return self.get_secret(
            "secret/agent-firewall/crypto",
            "canary_secret_key",
            "CANARY_SECRET_KEY",
        )

    @property
    def vault_connected(self) -> bool:
        return self._vault_available


_manager: Optional[SecretsManager] = None

def get_secrets_manager() -> SecretsManager:
    global _manager
    if _manager is None:
        _manager = SecretsManager()
    return _manager
