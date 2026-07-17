"""
CrossForge SSRF Agent — GraphQL Discovery Adapter
======================================================
WHY THIS MODULE EXISTS
------------------------
Flagged as a coverage gap in the Phase-1 evaluation: neither core/crawler.py
nor core/openapi_adapter.py has any GraphQL awareness. A REST-shaped crawl
of a GraphQL-backed app finds exactly one endpoint (`/graphql`) with zero
visible parameters — every argument that matters lives inside the query
document, invisible to link/form/JSON-body crawling. Any resolver argument
named `imageUrl`, `webhookEndpoint`, `avatarSrc`, etc. is a candidate SSRF
sink that a REST-oriented crawl cannot see at all.

This module mirrors core/openapi_adapter.py's design intentionally:
probe well-known paths, fetch a machine-readable schema (introspection
here, an OpenAPI/Swagger doc there), walk it for SSRF-plausible argument
names, emit Candidate objects directly. Same call-site shape in
core/agent.py, same "spec discovery is a separate, additive pass — not a
crawler responsibility" boundary. It deliberately duplicates
openapi_adapter's `_SSRF_PARAM_RE` pattern rather than importing it: these
two modules should each run cleanly standalone (see the Phase 1 rebuild
request this was written for) — a shared import would couple them for no
benefit, since the pattern is small enough that keeping two copies in sync
by inspection is trivial and a divergence in one doesn't risk breaking the
other's tests or callers.

WHY THE PARAMETER IS TAGGED "variables.<name>", NOT JUST "<name>"
-----------------------------------------------------------------------
core/http_client.py's generic BODY_JSON injection sets a single TOP-LEVEL
key in the JSON body equal to `candidate.parameter`. A naive GraphQL
candidate with `parameter="url"` and a variables-based query template
would have its payload written to `json_body["url"]` — a stray top-level
key the GraphQL server ignores — while the actual `variables.url` the
query references stays empty. That candidate would "run" every scan and
never once test anything. core/http_client.py's [P2-FIX] adds narrow,
additive support for a dotted `parameter` path to address into a nested
body_template dict (`variables.<name>` -> `json_body["variables"]["name"]`)
specifically so GraphQL candidates from this module actually reach the
resolver argument they claim to test — see that module for the full note.
Every non-GraphQL candidate in the codebase uses an undotted parameter
name, so this is a zero-risk addition for every existing candidate source.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Optional

import httpx

from core.models import Candidate, ParamLocation

logger = logging.getLogger("crossforge.graphql_adapter")

_GRAPHQL_PATHS = [
    "/graphql",
    "/graphql/",
    "/api/graphql",
    "/v1/graphql",
    "/v2/graphql",
    "/graphiql",
    "/query",
    "/api/query",
    "/gql",
]

# Deliberately mirrors core/openapi_adapter.py's _SSRF_PARAM_RE — see
# module docstring for why this is a standalone copy, not a shared import.
_SSRF_PARAM_RE = re.compile(
    r"url|uri|href|src|source|dest(?:ination)?|target|endpoint|host|"
    r"server|service|address|addr|path|location|link|redirect|forward|"
    r"proxy|fetch|load|resource|asset|import|export|callback|webhook|"
    r"notify(?:_url)?|ping|check|scan|crawl|download|upload|image|"
    r"avatar|icon|thumbnail|feed|rss|sitemap|manifest",
    re.IGNORECASE,
)

_INTROSPECTION_QUERY = """
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    types {
      name
      kind
      fields(includeDeprecated: true) {
        name
        args { name type { name kind ofType { name kind } } }
      }
    }
  }
}
"""

# GraphQL scalar arg types this module knows how to build a minimal,
# schema-valid variable declaration for. Anything else (enums, input
# object types, lists) is skipped — a malformed introspection-derived
# query that the server rejects outright would never reach the resolver
# and is worse than not testing that argument at all.
_SUPPORTED_SCALARS = {"String", "ID"}


async def discover_from_graphql(
    base_url: str,
    auth_headers: dict,
    timeout: float = 8.0,
) -> list[Candidate]:
    schema = await _fetch_introspection(base_url, auth_headers, timeout)
    if not schema:
        return []
    endpoint_url = schema["_endpoint_url"]
    return _extract_ssrf_candidates(schema, endpoint_url)


async def _fetch_introspection(
    base_url: str, auth_headers: dict, timeout: float,
) -> Optional[dict]:
    async with httpx.AsyncClient(
        verify=False, follow_redirects=True, timeout=timeout,
        headers={**auth_headers, "Content-Type": "application/json", "Accept": "application/json"},
    ) as client:
        for path in _GRAPHQL_PATHS:
            url = base_url.rstrip("/") + path
            try:
                resp = await client.post(url, json={"query": _INTROSPECTION_QUERY})
                if resp.status_code != 200:
                    continue
                data = resp.json()
                schema = data.get("data", {}).get("__schema")
                if schema and schema.get("types"):
                    logger.info("[GraphQL] Introspection succeeded at %s", url)
                    schema["_endpoint_url"] = url
                    return schema
            except Exception as exc:
                logger.debug("[GraphQL] %s -> %s", url, exc)
    return None


def _scalar_name(arg_type: dict) -> Optional[str]:
    """Unwrap NON_NULL/LIST wrappers to find the underlying scalar name,
    if any. Returns None for anything this module doesn't build a query
    for (input objects, enums, unsupported scalars)."""
    t = arg_type
    for _ in range(5):  # bounded unwrap depth, GraphQL type wrappers don't nest deeper in practice
        if t is None:
            return None
        if t.get("name"):
            return t["name"] if t["name"] in _SUPPORTED_SCALARS else None
        t = t.get("ofType")
    return None


def _extract_ssrf_candidates(schema: dict, endpoint_url: str) -> list[Candidate]:
    query_type_name    = (schema.get("queryType") or {}).get("name")
    mutation_type_name = (schema.get("mutationType") or {}).get("name")

    candidates: list[Candidate] = []
    for type_def in schema.get("types", []):
        type_name = type_def.get("name")
        if type_name not in (query_type_name, mutation_type_name):
            continue
        operation = "query" if type_name == query_type_name else "mutation"

        for field_def in type_def.get("fields") or []:
            field_name = field_def.get("name", "")
            for arg in field_def.get("args") or []:
                arg_name = arg.get("name", "")
                if not _SSRF_PARAM_RE.search(arg_name):
                    continue
                scalar = _scalar_name(arg.get("type") or {})
                if not scalar:
                    continue  # can't build a schema-valid minimal query for this arg type
                candidates.append(_make_candidate(
                    endpoint_url, operation, field_name, arg_name, scalar,
                ))
    return candidates


def _make_candidate(
    endpoint_url: str, operation: str, field_name: str, arg_name: str, scalar_type: str,
) -> Candidate:
    var_name = "v"
    query_doc = (
        f"{operation} SSRFProbe(${var_name}: {scalar_type}) "
        f"{{ {field_name}({arg_name}: ${var_name}) }}"
    )
    c = Candidate(
        target_url=endpoint_url,
        method="POST",
        # dotted path -> nested body_template["variables"]["v"] substitution,
        # see module docstring and core/http_client.py's [P2-FIX].
        parameter=f"variables.{var_name}",
        param_location=ParamLocation.BODY_JSON,
        original_value="",
        body_template={"query": query_doc, "variables": {}},
    )
    c.graphql_sourced = True
    return c
