"""
HELLHOUND SSRF v5.0 - OpenAPI / Swagger Adapter
=================================================
WHY THIS MODULE EXISTS
-----------------------
spider_adapter._PATH_SSRF_PARAM_MAP is a static heuristic table. Modern
API-first targets expose an OpenAPI 3.x or Swagger 2.x spec at a standard
path that enumerates EVERY parameter, its type, its location (query / body
/ header / path / cookie), and an example value.  Parsing that spec gives
us a dynamic, accurate candidate list that replaces guesswork with precision.

WHAT THIS MODULE DOES
  1. Probes a fixed set of well-known spec paths (GET /openapi.json etc.)
  2. Parses OpenAPI 3.x and Swagger 2.x schemas
  3. Converts every SSRF-plausible parameter into a Candidate
  4. Extracts requestBody JSON schema fields (OpenAPI 3.x body parameters
     that would otherwise be invisible to a pure-HTTP spider)
  5. Sets candidate.openapi_sourced = True so the HUD can report surface stats

WHY IT MATTERS
  - Covers authenticated API endpoints that the spider never visits
  - Finds parameters like "callback_url", "webhook", "destination" deep in
    POST request bodies that static crawling misses entirely
  - Eliminates substring-matched false candidates from _PATH_SSRF_PARAM_MAP
"""

from __future__ import annotations
import logging
import re
from typing import Any, Optional

import httpx

from core.models import Candidate, ParamLocation

logger = logging.getLogger(__name__)

# Standard spec discovery paths (ordered by commonality)
_SPEC_PATHS = [
    "/openapi.json",
    "/openapi.yaml",
    "/swagger.json",
    "/swagger.yaml",
    "/api-docs",
    "/api-docs/swagger.json",
    "/api/swagger.json",
    "/api/openapi.json",
    "/.well-known/openapi.json",
    "/v1/openapi.json",
    "/v2/openapi.json",
    "/v3/openapi.json",
    "/v1/swagger.json",
    "/v2/swagger.json",
    "/swagger/v1/swagger.json",
    "/swagger/v2/swagger.json",
    "/api/v1/swagger.json",
    "/api/v2/swagger.json",
    "/api/v3/openapi.json",
]

# Parameter names (lower-cased) that are SSRF-plausible
_SSRF_PARAM_RE = re.compile(
    r"url|uri|href|src|source|dest(?:ination)?|target|endpoint|host|"
    r"server|service|address|addr|path|location|link|redirect|forward|"
    r"proxy|fetch|load|resource|asset|import|export|callback|webhook|"
    r"notify(?:_url)?|ping|check|scan|crawl|download|upload|image|"
    r"avatar|icon|thumbnail|feed|rss|sitemap|manifest",
    re.IGNORECASE,
)

# Location mapping: OpenAPI param.in → ParamLocation
_LOCATION_MAP = {
    "query":  ParamLocation.QUERY,
    "header": ParamLocation.HEADER,
    "cookie": ParamLocation.COOKIE,
    "path":   ParamLocation.PATH,
    "body":   ParamLocation.BODY_JSON,   # Swagger 2.x
    "formData": ParamLocation.BODY_FORM, # Swagger 2.x
}


async def discover_from_spec(
    base_url: str,
    auth_headers: dict | None = None,
    timeout: float = 10.0,
) -> list[Candidate]:
    """
    Attempts to fetch an OpenAPI/Swagger spec from `base_url` and converts
    every SSRF-plausible parameter into a Candidate list.

    Parameters
    ----------
    base_url : str
        Scheme + host (+ optional port) of the target, e.g. "https://api.example.com"
    auth_headers : dict | None
        Optional auth headers to include in spec fetch requests.
    timeout : float
        Per-request timeout in seconds.

    Returns
    -------
    list[Candidate]
        Empty list if no spec is found or parseable.
    """
    spec = await _fetch_spec(base_url, auth_headers or {}, timeout)
    if spec is None:
        logger.debug("[OpenAPI] No spec found at %s", base_url)
        return []

    version = _detect_version(spec)
    logger.info("[OpenAPI] Found %s spec at %s (%d path(s))",
                version, base_url, len(spec.get("paths", {})))

    if version == "openapi3":
        candidates = _parse_openapi3(spec, base_url)
    else:
        candidates = _parse_swagger2(spec, base_url)

    logger.info("[OpenAPI] Extracted %d SSRF-plausible candidate(s) from spec", len(candidates))
    return candidates


# ---------------------------------------------------------------------------
# Spec fetching
# ---------------------------------------------------------------------------

async def _fetch_spec(
    base_url: str,
    auth_headers: dict,
    timeout: float,
) -> Optional[dict]:
    """Try each well-known spec path. Return the first parseable JSON/YAML spec."""
    async with httpx.AsyncClient(
        verify=False,
        follow_redirects=True,
        timeout=timeout,
        headers={**auth_headers, "Accept": "application/json, application/yaml, */*"},
    ) as client:
        for path in _SPEC_PATHS:
            url = base_url.rstrip("/") + path
            try:
                resp = await client.get(url)
                if resp.status_code != 200:
                    continue
                ct = resp.headers.get("content-type", "")
                spec = _parse_body(resp.text, ct)
                if spec and isinstance(spec, dict) and (
                    "paths" in spec or "openapi" in spec or "swagger" in spec
                ):
                    logger.info("[OpenAPI] Spec fetched from %s", url)
                    return spec
            except Exception as exc:
                logger.debug("[OpenAPI] %s → %s", url, exc)
    return None


def _parse_body(text: str, content_type: str) -> Optional[dict]:
    """Attempt JSON then YAML parse."""
    import json
    try:
        return json.loads(text)
    except Exception:
        pass
    try:
        import yaml  # PyYAML is already in requirements
        return yaml.safe_load(text)
    except Exception:
        return None


def _detect_version(spec: dict) -> str:
    if "openapi" in spec and str(spec["openapi"]).startswith("3"):
        return "openapi3"
    return "swagger2"


# ---------------------------------------------------------------------------
# OpenAPI 3.x parser
# ---------------------------------------------------------------------------

def _parse_openapi3(spec: dict, base_url: str) -> list[Candidate]:
    candidates: list[Candidate] = []
    servers = spec.get("servers", [{"url": base_url}])
    server_url = servers[0].get("url", base_url) if servers else base_url
    # Resolve relative server URLs
    if server_url.startswith("/"):
        server_url = base_url.rstrip("/") + server_url

    for path, path_item in spec.get("paths", {}).items():
        if not isinstance(path_item, dict):
            continue
        for method, operation in path_item.items():
            if method.lower() not in ("get", "post", "put", "patch", "delete", "options"):
                continue
            if not isinstance(operation, dict):
                continue

            full_url = server_url.rstrip("/") + path

            # --- Standard parameters (query / header / cookie / path)
            for param in operation.get("parameters", []) + path_item.get("parameters", []):
                if not isinstance(param, dict):
                    continue
                # Handle $ref resolution (basic, inline only)
                if "$ref" in param:
                    param = _resolve_ref(spec, param["$ref"]) or {}
                name     = param.get("name", "")
                location = param.get("in", "")
                example  = (
                    param.get("example")
                    or _schema_example(param.get("schema", {}))
                    or ""
                )
                if _SSRF_PARAM_RE.search(name) and location in _LOCATION_MAP:
                    candidates.append(_make_candidate(
                        url=full_url,
                        method=method.upper(),
                        name=name,
                        location=_LOCATION_MAP[location],
                        example=str(example),
                    ))

            # --- requestBody (OpenAPI 3.x only)
            request_body = operation.get("requestBody", {})
            if isinstance(request_body, dict):
                if "$ref" in request_body:
                    request_body = _resolve_ref(spec, request_body["$ref"]) or {}
                content = request_body.get("content", {})
                for media_type, media_obj in content.items():
                    if not isinstance(media_obj, dict):
                        continue
                    schema = media_obj.get("schema", {})
                    if "$ref" in schema:
                        schema = _resolve_ref(spec, schema["$ref"]) or {}

                    loc = (
                        ParamLocation.BODY_JSON
                        if "json" in media_type
                        else ParamLocation.BODY_FORM
                        if "form" in media_type
                        else None
                    )
                    if loc is None:
                        continue

                    # Extract top-level properties from object schema
                    props = schema.get("properties", {})
                    body_template = _build_body_template(props, spec)

                    for prop_name, prop_schema in props.items():
                        if not isinstance(prop_schema, dict):
                            continue
                        if _SSRF_PARAM_RE.search(prop_name):
                            example = (
                                prop_schema.get("example")
                                or _schema_example(prop_schema)
                                or ""
                            )
                            candidates.append(_make_candidate(
                                url=full_url,
                                method=method.upper(),
                                name=prop_name,
                                location=loc,
                                example=str(example),
                                body_template=body_template,
                            ))

    return candidates


# ---------------------------------------------------------------------------
# Swagger 2.x parser
# ---------------------------------------------------------------------------

def _parse_swagger2(spec: dict, base_url: str) -> list[Candidate]:
    candidates: list[Candidate] = []
    host     = spec.get("host", "")
    basePath = spec.get("basePath", "")
    schemes  = spec.get("schemes", ["https"])
    scheme   = schemes[0] if schemes else "https"
    server_url = f"{scheme}://{host}{basePath}" if host else base_url

    for path, path_item in spec.get("paths", {}).items():
        if not isinstance(path_item, dict):
            continue
        for method, operation in path_item.items():
            if method.lower() not in ("get", "post", "put", "patch", "delete"):
                continue
            if not isinstance(operation, dict):
                continue
            full_url = server_url.rstrip("/") + path

            for param in operation.get("parameters", []):
                if not isinstance(param, dict):
                    continue
                if "$ref" in param:
                    param = _resolve_ref(spec, param["$ref"]) or {}
                name     = param.get("name", "")
                location = param.get("in", "")
                example  = str(param.get("x-example", param.get("default", "")))

                if "$ref" in param.get("schema", {}):
                    schema = _resolve_ref(spec, param["schema"]["$ref"]) or {}
                    # body param with schema → extract properties
                    for prop_name, prop_schema in schema.get("properties", {}).items():
                        if _SSRF_PARAM_RE.search(prop_name):
                            candidates.append(_make_candidate(
                                url=full_url,
                                method=method.upper(),
                                name=prop_name,
                                location=ParamLocation.BODY_JSON,
                                example="",
                            ))
                    continue

                if _SSRF_PARAM_RE.search(name) and location in _LOCATION_MAP:
                    candidates.append(_make_candidate(
                        url=full_url,
                        method=method.upper(),
                        name=name,
                        location=_LOCATION_MAP[location],
                        example=example,
                    ))

    return candidates


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _make_candidate(
    url: str,
    method: str,
    name: str,
    location: ParamLocation,
    example: str = "",
    body_template: dict | None = None,
) -> Candidate:
    c = Candidate(
        target_url=url,
        method=method,
        parameter=name,
        param_location=location,
        original_value=example,
        body_template=body_template,
    )
    c.openapi_sourced = True
    return c


def _resolve_ref(spec: dict, ref: str) -> Optional[dict]:
    """Resolve a local JSON $ref like '#/components/schemas/MyModel'."""
    if not ref.startswith("#/"):
        return None
    parts = ref.lstrip("#/").split("/")
    node: Any = spec
    for part in parts:
        if not isinstance(node, dict):
            return None
        node = node.get(part.replace("~1", "/").replace("~0", "~"))
    return node if isinstance(node, dict) else None


def _schema_example(schema: dict) -> Any:
    """Extract a usable example value from a JSON Schema object."""
    if "example" in schema:
        return schema["example"]
    t = schema.get("type", "string")
    if t == "string":
        fmt = schema.get("format", "")
        if "uri" in fmt or "url" in fmt:
            return "http://example.com"
        return ""
    if t == "integer":
        return schema.get("default", 0)
    return ""


def _build_body_template(props: dict, spec: dict) -> dict:
    """
    Build a minimal body dict from schema properties for use as
    Candidate.body_template. Provides placeholder values for all
    non-SSRF fields so the probe is a valid request.
    """
    template = {}
    for name, schema in props.items():
        if isinstance(schema, dict):
            if "$ref" in schema:
                schema = _resolve_ref(spec, schema["$ref"]) or {}
            t = schema.get("type", "string")
            if t == "string":
                template[name] = schema.get("default", schema.get("example", ""))
            elif t in ("integer", "number"):
                template[name] = schema.get("default", 0)
            elif t == "boolean":
                template[name] = schema.get("default", False)
            elif t == "array":
                template[name] = []
            elif t == "object":
                template[name] = {}
            else:
                template[name] = ""
    return template
