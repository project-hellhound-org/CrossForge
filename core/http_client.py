"""
HELLHOUND SSRF v5.0 - HTTP Client Layer
==========================================
v5 fixes applied:
  [P0-FIX] GET + BODY_JSON correction → auto-promotes to POST
  [P0-FIX] Header injection blocklist — semantically invalid headers
           (Host, Content-Length, etc.) are never injected with SSRF payloads
  [P1-FIX] body_template None-guard — safe .copy() with type check
  [P1-FIX] Content-Type header injected automatically for JSON bodies
  [v5-NEW] raw_request/raw_response captured as clean printable strings
           with full body snippet for evidence PoC quality
"""

from __future__ import annotations
import asyncio
import json
import socket
import time
from typing import Any

import httpx

from core.models import Candidate, ParamLocation, ProbeResult


# ---------------------------------------------------------------------------
# [P0-FIX] Header injection blocklist
# ---------------------------------------------------------------------------
# These headers carry protocol-level semantics. Injecting SSRF payloads
# into them produces malformed requests (400 errors, gzip failures) that
# register as spurious anomalies and trigger false Phase 6 gates.
# The list is conservative — when in doubt a header is BLOCKED.
# Override via config.yaml http.header_injection_allowlist.
_BLOCKED_INJECTION_HEADERS: frozenset[str] = frozenset({
    "host",
    "content-length",
    "transfer-encoding",
    "accept-encoding",
    "content-encoding",
    "connection",
    "upgrade",
    "expect",
    "te",
    "trailer",
    "proxy-connection",
    "keep-alive",
})


class RateLimiter:
    """Token-bucket rate limiter shared across all requests for a target."""

    def __init__(self, requests_per_second: float = 25.0, burst: int = 50):
        self.rate = requests_per_second
        self.capacity = burst
        self.tokens = float(burst)
        self.updated = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self.updated
            self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
            self.updated = now
            if self.tokens < 1:
                wait = (1 - self.tokens) / self.rate
                await asyncio.sleep(wait)
                self.tokens = 0.0
            else:
                self.tokens -= 1.0


class HttpClient:
    """
    Async HTTP client for Phases 1, 3, and 4.
    Wraps httpx.AsyncClient with:
      - Token-bucket rate limiting
      - Payload injection per ParamLocation
      - Redirect-chain tracking
      - Raw request/response capture for PoC/evidence quality
      - [v5] GET+BODY_JSON auto-correction to POST
      - [v5] Header injection blocklist enforcement
    """

    def __init__(
        self,
        rate_limiter: RateLimiter | None = None,
        timeout: float = 8.0,
        proxy: str | None = None,
        follow_redirects: bool = True,
        max_redirects: int = 5,
        header_injection_allowlist: set[str] | None = None,
    ):
        self.rate_limiter = rate_limiter or RateLimiter()
        self.timeout = timeout
        self.follow_redirects = follow_redirects
        self.max_redirects = max_redirects

        # Operator can whitelist specific blocked headers if the engagement
        # specifically targets them (e.g. testing Host header SSRF manually)
        self._blocked_headers = (
            _BLOCKED_INJECTION_HEADERS
            if not header_injection_allowlist
            else _BLOCKED_INJECTION_HEADERS - {h.lower() for h in header_injection_allowlist}
        )

        # NOTE: verify=False is intentional for internal/staging targets.
        client_kwargs: dict[str, Any] = {
            "timeout": timeout,
            "follow_redirects": False,  # followed manually to capture chain
            "verify": False,
        }
        if proxy:
            client_kwargs["proxy"] = proxy
        self._client = httpx.AsyncClient(**client_kwargs)

    async def close(self) -> None:
        await self._client.aclose()

    # ------------------------------------------------------------------
    # Payload injection
    # ------------------------------------------------------------------

    def _inject(
        self,
        candidate: Candidate,
        value: Any,
    ) -> tuple[str, str, dict, dict, dict | None, dict | None, dict, dict]:
        """
        Computes the effective (url, method, params, path_params,
        json_body, data_body, headers, cookies) for this probe.

        Returns
        -------
        (url, method, params, json_body, data_body, headers, cookies)
        """
        url = candidate.target_url
        method = candidate.method.upper()
        params: dict[str, Any] = {}
        json_body: dict | None = None
        data_body: dict | None = None
        headers = dict(candidate.headers)
        cookies = dict(candidate.cookies)

        loc = candidate.param_location

        # ---- [P0-FIX] GET + BODY_JSON → auto-promote to POST ----------
        if loc == ParamLocation.BODY_JSON and method == "GET":
            method = "POST"

        # ---- [P0-FIX] Header blocklist ---------------------------------
        if loc == ParamLocation.HEADER:
            if candidate.parameter.lower() in self._blocked_headers:
                # Return unmodified request — caller will detect no anomaly
                # and the candidate gets a confidence_reduction flag added
                candidate.confidence_reduction_flags.append("header_blocklisted")
                return url, method, params, json_body, data_body, headers, cookies

        # ---- Inject value per location ---------------------------------
        if loc == ParamLocation.QUERY:
            # BUG 4 FIX: Restore the non-tested context params first (the
            # other query params that were in the original observed URL but
            # are not the param being injected), then overwrite with the
            # payload value for the param being tested. This way the server
            # sees: ?other=original_value&tested_param=SSRF_PAYLOAD
            # instead of: ?existing_qs_with_original_value&tested_param=SSRF_PAYLOAD
            # (which was the duplicate-param bug).
            if candidate.baseline_query_context:
                params.update(candidate.baseline_query_context)
            params[candidate.parameter] = value

        elif loc == ParamLocation.HEADER:
            headers[candidate.parameter] = str(value)

        elif loc == ParamLocation.COOKIE:
            cookies[candidate.parameter] = str(value)

        elif loc == ParamLocation.BODY_JSON:
            # [P1-FIX] Safe copy with type check before .update()
            if isinstance(candidate.body_template, dict):
                json_body = dict(candidate.body_template)
            else:
                json_body = {}
            # [P2-FIX] Dotted parameter path -> nested substitution.
            # Added for core/graphql_adapter.py, whose candidates need the
            # payload written into json_body["variables"][name], not a
            # stray top-level json_body[name] key the server would ignore
            # entirely — a GraphQL server only reads declared variables.
            # Every OTHER candidate source in this codebase (spider_adapter,
            # openapi_adapter, the flat-array loader) generates undotted
            # parameter names, so this branch is unreachable for them and
            # changes nothing about their existing behaviour.
            if "." in candidate.parameter:
                *path_parts, leaf = candidate.parameter.split(".")
                node = json_body
                for part in path_parts:
                    nxt = node.get(part)
                    if not isinstance(nxt, dict):
                        nxt = {}
                        node[part] = nxt
                    node = nxt
                node[leaf] = value
            else:
                json_body[candidate.parameter] = value
            # Ensure Content-Type is set
            headers.setdefault("Content-Type", "application/json")

        elif loc in (ParamLocation.BODY_FORM, ParamLocation.BODY_MULTIPART):
            if isinstance(candidate.body_template, dict):
                data_body = dict(candidate.body_template)
            else:
                data_body = {}
            data_body[candidate.parameter] = value

        elif loc == ParamLocation.PATH:
            url = candidate.target_url.replace(
                "{" + candidate.parameter + "}", str(value)
            )

        return url, method, params, json_body, data_body, headers, cookies

    # ------------------------------------------------------------------
    # Core send
    # ------------------------------------------------------------------

    async def send(
        self,
        candidate: Candidate,
        payload_value: Any,
        payload_category: str,
    ) -> ProbeResult:
        await self.rate_limiter.acquire()

        url, method, params, json_body, data_body, headers, cookies = self._inject(
            candidate, payload_value
        )

        redirect_chain: list[str] = []
        start = time.monotonic()
        status_code = 0
        content = b""
        resp_headers: dict = {}
        raw_request = _fmt_request(method, url, params, json_body, data_body, headers)
        raw_response = ""
        error_class: str | None = None
        resolved_ip = _resolve_host(url)
        current_url = url

        try:
            for hop in range(self.max_redirects + 1):
                resp = await self._client.request(
                    method,
                    current_url,
                    params=params if hop == 0 else None,
                    json=json_body if hop == 0 else None,
                    data=data_body if hop == 0 else None,
                    headers=headers,
                    cookies=cookies,
                )
                status_code = resp.status_code
                content = resp.content
                resp_headers = dict(resp.headers)

                # Capture clean raw request on first hop
                if hop == 0:
                    req = resp.request
                    raw_request = _fmt_request(
                        str(req.method),
                        str(req.url),
                        {},
                        json_body,
                        data_body,
                        dict(req.headers),
                    )

                if resp.is_redirect and self.follow_redirects:
                    location = resp.headers.get("location", "")
                    if location:
                        redirect_chain.append(location)
                        current_url = str(resp.url.join(location))
                    continue
                break

            raw_response = _fmt_response(status_code, resp_headers, content)

        except httpx.ConnectError as exc:
            error_class = (
                "connection_refused"
                if "refused" in str(exc).lower()
                else "connection_error"
            )
        except (httpx.ConnectTimeout, httpx.ReadTimeout,
                httpx.WriteTimeout, httpx.PoolTimeout):
            error_class = "timeout"
        except httpx.UnsupportedProtocol:
            error_class = "unsupported_protocol"
        except Exception as exc:
            msg = str(exc).lower()
            if any(k in msg for k in (
                "name or service not known",
                "nodename nor servname",
                "getaddrinfo",
                "name resolution",
                "temporary failure",
            )):
                error_class = "dns_failure"
            else:
                error_class = "other_error"

        elapsed = time.monotonic() - start

        # Classify success_foreign: redirect happened or external content received
        if error_class is None and status_code:
            if redirect_chain:
                error_class = "success_foreign"
            else:
                error_class = None  # clean success — not anomalous by itself

        candidate.requests_sent += 1

        return ProbeResult(
            candidate_id=candidate.candidate_id,
            payload=str(payload_value),
            payload_category=payload_category,
            status_code=status_code,
            content_length=len(content),
            elapsed=elapsed,
            redirect_depth=len(redirect_chain),
            redirect_chain=redirect_chain,
            headers=resp_headers,
            body_snippet=content[:2000].decode(errors="replace"),
            raw_request=raw_request,
            raw_response=raw_response,
            error_class=error_class,
            resolved_ip=resolved_ip,
        )

    # ------------------------------------------------------------------
    # Raw GET helper (used by evidence_engine and openapi_adapter)
    # ------------------------------------------------------------------

    async def get_raw(self, url: str, headers: dict | None = None) -> ProbeResult:
        """
        Sends a plain GET to `url` with optional `headers`.
        Returns a ProbeResult. Not rate-limited (used internally by
        evidence_engine / openapi_adapter for targeted probes).
        """
        start = time.monotonic()
        status_code = 0
        content = b""
        resp_headers: dict = {}
        error_class: str | None = None

        try:
            resp = await self._client.get(
                url,
                headers=headers or {},
                follow_redirects=True,
            )
            status_code = resp.status_code
            content = resp.content
            resp_headers = dict(resp.headers)
        except Exception as exc:
            msg = str(exc).lower()
            if "refused" in msg:
                error_class = "connection_refused"
            elif "timeout" in msg:
                error_class = "timeout"
            elif "getaddrinfo" in msg or "name" in msg:
                error_class = "dns_failure"
            else:
                error_class = "other_error"

        elapsed = time.monotonic() - start
        # Build a minimal ProbeResult
        from core.models import ProbeResult as PR
        return PR(
            candidate_id="",
            payload=url,
            payload_category="raw_get",
            status_code=status_code,
            content_length=len(content),
            elapsed=elapsed,
            redirect_depth=0,
            redirect_chain=[],
            headers=resp_headers,
            body_snippet=content[:4096].decode(errors="replace"),
            error_class=error_class,
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _fmt_request(
    method: str,
    url: str,
    params: dict,
    json_body: dict | None,
    data_body: dict | None,
    headers: dict,
) -> str:
    lines = [f"{method} {url}"]
    for k, v in headers.items():
        lines.append(f"{k}: {v}")
    if json_body is not None:
        lines.append("")
        lines.append(json.dumps(json_body))
    elif data_body is not None:
        lines.append("")
        lines.append("&".join(f"{k}={v}" for k, v in data_body.items()))
    return "\n".join(lines)


def _fmt_response(status: int, headers: dict, content: bytes) -> str:
    lines = [f"HTTP {status}"]
    for k, v in headers.items():
        lines.append(f"{k}: {v}")
    lines.append("")
    lines.append(content[:2000].decode(errors="replace"))
    return "\n".join(lines)


def _resolve_host(url: str) -> str | None:
    """
    Best-effort DNS resolution at request time.
    Used by Phase 7 DNS-rebinding detection (compare against Phase 1 baseline IP).
    """
    try:
        host = httpx.URL(url).host
        if not host:
            return None
        return socket.gethostbyname(host)
    except (httpx.InvalidURL, socket.gaierror, UnicodeError, ValueError):
        return None
