"""
RAVAGER SSRF v2.0.0 - Phase 5: OOB Correlation Hub
=====================================================
v2.0 changes:
  [v2-FIX] Proxy-everything: OOB polling now routes through the
           configured --proxy for consistent networking behavior and
           full visibility in tools like Burp Suite.
  [v2-NEW] oob_wait daemon mode: after the main scan completes, the
           hub continues polling for stored/second-order SSRF callbacks
           for a configurable duration (--oob-wait flag).
  [v2-NEW] Structured interaction logging via console helpers instead
           of raw logger.info dumps.

Retained from v1:
  originating_request capture when OOB server returns raw HTTP
  interaction body (self-hosted Interactsh with --full-response)
  Host header SSRF OOB support
  poll_error_count surfaced in get_health()
"""

from __future__ import annotations
import asyncio
import base64
import datetime
import ipaddress
import logging
import re
import secrets
import time
from collections import defaultdict

import httpx

from core.models import OOBEvent
from core.console import ok, info, warn, dim, found, color, C, tprint

logger = logging.getLogger(__name__)


class OOBHub:
    """
    Manages per-candidate OOB tokens against an Interactsh-compatible server.
    Maintains a queryable correlation timeline for Phase 5 blind SSRF confirmation.
    """

    def __init__(
        self,
        server_url: str,
        poll_interval: float = 5.0,
        proxy: str | None = None,
        oob_wait: float = 60.0,
    ):
        self.server_url    = server_url.rstrip("/")
        self.poll_interval = poll_interval
        self.oob_wait      = oob_wait

        self._token_owner: dict[str, str]          = {}
        self.timeline:     dict[str, list[OOBEvent]] = defaultdict(list)

        # [v2-FIX] Proxy-everything: route OOB polling through the
        # configured proxy for consistent networking and Burp visibility.
        client_kwargs: dict = {
            "timeout": 10.0,
            "verify": False,  # self-hosted Interactsh typically uses self-signed TLS
        }
        if proxy:
            client_kwargs["proxy"] = proxy

        self._client = httpx.AsyncClient(**client_kwargs)
        self._polling_task: asyncio.Task | None = None

        self.poll_error_count: int      = 0
        self.last_poll_error:  str | None = None
        self._total_interactions: int   = 0

    # ------------------------------------------------------------------
    # Token management
    # ------------------------------------------------------------------

    def issue_token(self, candidate_id: str) -> str:
        """Generates a per-candidate correlation token."""
        token = secrets.token_hex(8)
        self._token_owner[token] = candidate_id
        return token

    def collaborator_host(self) -> str:
        """Hostname portion to use in OOB canary payloads."""
        try:
            return httpx.URL(self.server_url).host or self.server_url
        except httpx.InvalidURL:
            return self.server_url

    # ------------------------------------------------------------------
    # Polling lifecycle
    # ------------------------------------------------------------------

    async def start_polling(self) -> None:
        self._polling_task = asyncio.create_task(self._poll_loop())

    async def stop_polling(self) -> None:
        if self._polling_task:
            self._polling_task.cancel()
            try:
                await self._polling_task
            except asyncio.CancelledError:
                pass
        await self._client.aclose()

    async def _poll_loop(self) -> None:
        while True:
            try:
                await self._poll_once()
                self.poll_error_count = 0
            except httpx.HTTPError as exc:
                self.poll_error_count += 1
                self.last_poll_error = str(exc)
                logger.warning(
                    "OOB poll failed (%d): %s — FIRM-tier confirmation may be delayed.",
                    self.poll_error_count, exc,
                )
            except Exception as exc:
                self.poll_error_count += 1
                self.last_poll_error = str(exc)
                logger.exception("Unexpected error in OOB poll loop: %s", exc)
            await asyncio.sleep(self.poll_interval)

    async def _poll_once(self) -> None:
        """Polls /poll endpoint and ingests new interactions."""
        resp = await self._client.get(f"{self.server_url}/poll")
        if resp.status_code != 200:
            return

        payload = resp.json()
        for raw in payload.get("data", []) or []:
            try:
                decoded = base64.b64decode(raw).decode(errors="replace")
            except (ValueError, UnicodeDecodeError):
                decoded = raw
            self._ingest_interaction(decoded)

    def _ingest_interaction(self, raw: str) -> None:
        for token, candidate_id in self._token_owner.items():
            if token not in raw:
                continue

            # Extract originating HTTP request body if present
            orig_req: str | None = None
            raw_req_match = re.search(
                r'"raw-request"\s*:\s*"([^"]+)"', raw
            )
            if raw_req_match:
                try:
                    orig_req = base64.b64decode(
                        raw_req_match.group(1)
                    ).decode(errors="replace")
                except Exception:
                    orig_req = raw_req_match.group(1)

            event = OOBEvent(
                token=token,
                candidate_id=candidate_id,
                protocol=_extract_protocol(raw),
                received_at=datetime.datetime.utcnow(),
                remote_addr=_extract_remote_addr(raw),
                raw=raw,
                originating_request=orig_req,
            )
            self.timeline[candidate_id].append(event)
            self._total_interactions += 1

            # [v2-FIX] Structured console output instead of raw logger dump.
            # Raw interaction data is only logged at DEBUG level.
            found(
                f"OOB callback: {color(candidate_id[:8], C.BWHITE)}  "
                f"protocol={color(event.protocol, C.BCYAN)}  "
                f"remote={color(event.remote_addr or '?', C.DIM)}"
            )
            logger.debug(
                "OOB raw interaction: candidate=%s token=%s raw=%s",
                candidate_id[:8], token, raw[:200],
            )

    # ------------------------------------------------------------------
    # [v2-NEW] Daemon mode for stored/second-order SSRF
    # ------------------------------------------------------------------

    async def run_daemon(
        self,
        report: "ScanReport",
        findings_by_candidate: "dict[str, Finding]",
    ) -> list[str]:
        """
        Continues polling the OOB server for oob_wait seconds after the
        main scan completes. Any late-arriving interactions are correlated
        with candidates and their findings are upgraded to FIRM tier.

        Returns a list of candidate_ids that received late callbacks.

        This is the stored/second-order SSRF detection mechanism:
        - Webhooks that fire after registration
        - PDF renders that fetch URLs asynchronously
        - Email templates processed in background queues
        - Import/export jobs that run on a schedule
        """
        if self.oob_wait <= 0:
            return []

        tprint()
        info(
            f"Entering OOB daemon mode — polling for "
            f"{color(f'{self.oob_wait:.0f}s', C.BWHITE, C.BOLD)} "
            f"for stored/second-order SSRF callbacks..."
        )

        upgraded: list[str] = []
        known_before = set()
        for cid, events in self.timeline.items():
            if events:
                known_before.add(cid)

        t_start = time.monotonic()
        while (time.monotonic() - t_start) < self.oob_wait:
            try:
                await self._poll_once()
            except Exception as exc:
                logger.debug("Daemon poll error: %s", exc)

            # Check for new interactions
            for cid, events in self.timeline.items():
                if cid not in known_before and events:
                    known_before.add(cid)
                    upgraded.append(cid)
                    ok(
                        f"Stored SSRF confirmed: {color(cid[:8], C.BRED, C.BOLD)} "
                        f"received late OOB callback after "
                        f"{color(f'{time.monotonic() - t_start:.1f}s', C.BWHITE)} delay"
                    )

            elapsed = time.monotonic() - t_start
            remaining = self.oob_wait - elapsed
            if remaining > 0:
                await asyncio.sleep(min(self.poll_interval, remaining))

        if upgraded:
            ok(
                f"Daemon mode complete: {color(str(len(upgraded)), C.BRED, C.BOLD)} "
                f"stored SSRF callback(s) confirmed"
            )
        else:
            dim(f"Daemon mode complete: no late callbacks received in {self.oob_wait:.0f}s")

        return upgraded

    # ------------------------------------------------------------------
    # Query API
    # ------------------------------------------------------------------

    def has_interaction(self, candidate_id: str) -> bool:
        return bool(self.timeline.get(candidate_id))

    def is_async_pattern(
        self,
        candidate_id: str,
        min_gap_seconds: float = 1.5,
    ) -> bool:
        """True if ≥2 callbacks arrived with a processing delay gap."""
        events = sorted(
            self.timeline.get(candidate_id, []),
            key=lambda e: e.received_at,
        )
        if len(events) < 2:
            return False
        for a, b in zip(events, events[1:]):
            if (b.received_at - a.received_at).total_seconds() >= min_gap_seconds:
                return True
        return False

    def internal_pivot_targets(self, candidate_id: str) -> list[str]:
        """RFC1918 remote_addr values from this candidate's OOB events."""
        targets: list[str] = []
        for event in self.timeline.get(candidate_id, []):
            if not event.remote_addr:
                continue
            try:
                ip = ipaddress.ip_address(event.remote_addr)
                if ip.is_private:
                    targets.append(event.remote_addr)
            except ValueError:
                continue
        return targets

    def get_health(self) -> dict:
        """Returns poll health stats for the operator/HUD."""
        return {
            "poll_error_count":    self.poll_error_count,
            "last_poll_error":     self.last_poll_error,
            "total_interactions":  self._total_interactions,
            "registered_tokens":   len(self._token_owner),
        }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _extract_protocol(raw: str) -> str:
    raw_lower = raw.lower()
    if '"protocol":"dns"' in raw_lower or '"protocol": "dns"' in raw_lower:
        return "dns"
    if "smb" in raw_lower:
        return "smb"
    return "http"


def _extract_remote_addr(raw: str) -> str | None:
    m = re.search(r'"remote-address"\s*:\s*"([^"]+)"', raw)
    return m.group(1) if m else None
