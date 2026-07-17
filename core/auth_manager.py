"""
HELLHOUND SSRF v5.0 - Authentication Manager
=============================================
WHY THIS MODULE EXISTS
-----------------------
Most enterprise APIs require authentication for every endpoint. Without
JWT / session injection, Phase 4 probes against authenticated endpoints
return 401/403 which register as WAF blocks, and candidates never get
meaningful differential data. This module:

  1. Extracts authentication tokens from spider_adapter's leaked_credentials
     capture (Authorization headers, Set-Cookie, X-API-Key).
  2. Provides an inject() method that patches a Candidate's headers/cookies
     in-place before scanning, so the rest of the pipeline is unaware.
  3. Optionally accepts a manually specified token via config.yaml for
     full authenticated scan paths.
  4. Detects JWT expiry (exp claim check) and warns the operator.

PHILOSOPHY: Auth injection is PASSIVE — we never attempt to acquire tokens
via brute-force or credential stuffing. We only use tokens that were
already present in the spider's traffic capture or supplied by the operator.
This keeps HELLHOUND's behaviour within the scope of an authorized assessment.
"""

from __future__ import annotations
import base64
import json
import logging
import re
import time
from dataclasses import dataclass
from typing import Optional

from core.models import Candidate, ParamLocation

logger = logging.getLogger(__name__)

# Headers that carry bearer / API key tokens
_BEARER_HEADERS = {
    "authorization",
    "x-api-key",
    "x-auth-token",
    "x-access-token",
    "token",
    "api-key",
    "apikey",
}

# Regex for JWT shape: three base64url segments separated by dots
_JWT_RE = re.compile(
    r"^[A-Za-z0-9_-]{2,}\.[A-Za-z0-9_-]{2,}\.[A-Za-z0-9_-]{2,}$"
)

# Regex for "Bearer <token>" scheme
_BEARER_RE = re.compile(r"^Bearer\s+(.+)$", re.IGNORECASE)


@dataclass
class AuthContext:
    jwt_token:    Optional[str] = None   # raw JWT string
    api_key:      Optional[str] = None   # raw API key
    api_key_header: str         = "X-Api-Key"
    cookies:      dict          = None   # session cookies

    # Decoded JWT claims (informational, not used for signing)
    jwt_sub:      Optional[str] = None
    jwt_exp:      Optional[int] = None   # Unix timestamp

    def __post_init__(self):
        if self.cookies is None:
            self.cookies = {}

    @property
    def has_any(self) -> bool:
        return bool(self.jwt_token or self.api_key or self.cookies)

    @property
    def jwt_expired(self) -> bool:
        if self.jwt_exp is None:
            return False
        return time.time() > self.jwt_exp


class AuthManager:
    """
    Central auth context manager for a scan session.

    Usage (inside agent.py):
        auth_mgr = AuthManager.from_config(config, spider_result)
        if auth_mgr.has_auth:
            auth_mgr.inject(candidate)
    """

    def __init__(self, auth_ctx: AuthContext):
        self._ctx = auth_ctx
        if self._ctx.jwt_expired:
            logger.warning(
                "[AuthManager] JWT token has EXPIRED (exp=%s). "
                "Authenticated probes will likely return 401. "
                "Supply a fresh token via config.yaml auth.bearer_token.",
                self._ctx.jwt_exp,
            )
        elif self._ctx.jwt_token:
            logger.info(
                "[AuthManager] JWT auth ready (sub=%s, exp=%s)",
                self._ctx.jwt_sub or "unknown",
                self._ctx.jwt_exp or "no-exp",
            )
        elif self._ctx.api_key:
            logger.info(
                "[AuthManager] API key auth ready (header: %s)",
                self._ctx.api_key_header,
            )
        elif self._ctx.cookies:
            logger.info(
                "[AuthManager] Cookie-based auth ready (%d cookie(s))",
                len(self._ctx.cookies),
            )

    # ------------------------------------------------------------------

    @classmethod
    def from_config(
        cls,
        config: dict,
        leaked_creds: list[dict] | None = None,
    ) -> "AuthManager":
        """
        Builds an AuthManager by merging:
          1. Operator-supplied config.auth values (highest priority)
          2. Leaked credentials from spider_adapter (auto-detected)
        """
        auth_cfg = config.get("auth", {}) or {}
        ctx = AuthContext()

        # --- Priority 1: explicit config
        if auth_cfg.get("bearer_token"):
            raw = str(auth_cfg["bearer_token"]).strip()
            ctx.jwt_token = raw
            _populate_jwt_claims(ctx, raw)
            logger.debug("[AuthManager] Using operator-supplied bearer token")

        elif auth_cfg.get("api_key"):
            ctx.api_key = str(auth_cfg["api_key"]).strip()
            ctx.api_key_header = auth_cfg.get("api_key_header", "X-Api-Key")

        if auth_cfg.get("cookies"):
            ctx.cookies.update(auth_cfg["cookies"])

        # --- Priority 2: leaked creds from spider capture
        if leaked_creds and not ctx.jwt_token and not ctx.api_key:
            _extract_from_leaked(ctx, leaked_creds)

        return cls(ctx)

    # ------------------------------------------------------------------

    @property
    def has_auth(self) -> bool:
        return self._ctx.has_any

    def inject(self, candidate: Candidate) -> None:
        """
        Mutates `candidate` in-place by adding auth headers / cookies.
        Called once per candidate before Phase 4 probing begins.
        Skips injection for header-location candidates whose parameter
        IS the auth header (avoid double-injection).
        """
        if not self._ctx.has_any:
            return

        # Skip if this candidate IS the auth header itself
        if candidate.param_location == ParamLocation.HEADER:
            if candidate.parameter.lower() in _BEARER_HEADERS:
                return

        if self._ctx.jwt_token:
            # Don't overwrite if operator already passed it in headers
            if "Authorization" not in candidate.headers:
                candidate.headers["Authorization"] = f"Bearer {self._ctx.jwt_token}"

        elif self._ctx.api_key:
            hdr = self._ctx.api_key_header
            if hdr not in candidate.headers:
                candidate.headers[hdr] = self._ctx.api_key

        if self._ctx.cookies:
            candidate.cookies.update(self._ctx.cookies)

        candidate.auth_injected = True


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _extract_from_leaked(ctx: AuthContext, leaked: list[dict]) -> None:
    """Try to pull a usable JWT or API key from spider-captured credentials."""
    for item in leaked:
        header = item.get("header", "").lower()
        value  = str(item.get("value", "")).strip()

        if not value:
            continue

        # Strip "Bearer " prefix
        m = _BEARER_RE.match(value)
        if m:
            value = m.group(1)

        if header in _BEARER_HEADERS:
            if _JWT_RE.match(value):
                ctx.jwt_token = value
                _populate_jwt_claims(ctx, value)
                logger.info(
                    "[AuthManager] Extracted JWT from leaked header '%s' (sub=%s)",
                    header, ctx.jwt_sub or "unknown",
                )
                return
            else:
                # Treat as opaque API key
                ctx.api_key = value
                ctx.api_key_header = _canonical_header(header)
                logger.info(
                    "[AuthManager] Extracted API key from leaked header '%s'", header
                )
                return

        if header == "cookie":
            for kv in value.split(";"):
                k, _, v = kv.strip().partition("=")
                if k:
                    ctx.cookies[k.strip()] = v.strip()
            logger.info(
                "[AuthManager] Extracted %d session cookie(s) from spider capture",
                len(ctx.cookies),
            )


def _populate_jwt_claims(ctx: AuthContext, token: str) -> None:
    """Decode the JWT payload (no signature verification — informational only)."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return
        payload_b64 = parts[1]
        # Add padding
        payload_b64 += "=" * (4 - len(payload_b64) % 4)
        payload = json.loads(base64.urlsafe_b64decode(payload_b64))
        ctx.jwt_sub = str(payload.get("sub", payload.get("user_id", "")))
        ctx.jwt_exp = payload.get("exp")
    except Exception:
        pass  # Malformed JWT — treat as opaque token


def _canonical_header(header_lower: str) -> str:
    """x-api-key → X-Api-Key"""
    return "-".join(p.capitalize() for p in header_lower.split("-"))
