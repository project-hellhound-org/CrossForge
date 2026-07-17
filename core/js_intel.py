"""
CrossForge SSRF Agent — JS Static-Analysis Depth (Phase 1 addition)
========================================================================
WHY THIS MODULE EXISTS
------------------------
core/crawler.py's `_JS_ENDPOINT_PATTERNS` only match calls whose URL is a
LITERAL string: `fetch("https://api.x.com/y")`. In any bundled/minified
production JS (which is most of it), the URL is built from a variable or
concatenation instead:

    const API_BASE = "https://api.x.com";
    fetch(API_BASE + "/proxy?url=" + userInput);
    // or, after minification:
    const a="https://api.x.com";fetch(a+"/proxy")

A pure literal-string regex finds nothing in either case — not because the
endpoint isn't there, but because the string it needs is one hop away
through a variable. This module adds that one hop: build a map of
variable-name -> string-literal-value from simple assignments and object
literals in the same script, then re-run the existing call-site patterns
against identifiers found in that map.

This module is ADDITIVE ONLY. It does not replace or modify
crawler.py's `_JS_ENDPOINT_PATTERNS` / `_JS_PATH_FALLBACK_RE` — those keep
running exactly as before. `enrich()` returns extra raw path/URL strings
for the crawler to fold into the same `_resolve()` / `_record_endpoint_from_url()`
call sites it already uses for its own regex hits, so a JS-discovered
endpoint via either path gets IDENTICAL downstream treatment (still no
named param, still falls through to spider_adapter's word-boundary
path-keyword inference — see crawler.py's `_record_endpoint_from_url`
docstring note for why that's intentional).

WHAT THIS DELIBERATELY DOES NOT DO
--------------------------------------
No JS execution, no AST parsing, no bundler-aware source-map resolution.
This is the same "static pattern matching, no dependency" philosophy
crawler.py already uses for its own JS pass — deeper static resolution
(variable hop + a handful of well-known framework shapes) without paying
for a JS engine. Genuinely dynamic URL construction (built at runtime from
API responses, computed values, etc.) is out of reach for any static
pass — that's what the headless-render escalation in crawler.py is for.
"""

from __future__ import annotations

import re

# ---------------------------------------------------------------------------
# Variable -> string-literal map
# ---------------------------------------------------------------------------

# `const/let/var NAME = "VALUE"` — simple top-level string assignment.
_VAR_ASSIGN_RE = re.compile(
    r"""(?:const|let|var)\s+([A-Za-z_$][\w$]{0,60})\s*=\s*[`'"]([^`'"]{1,300})[`'"]""",
)

# `NAME: "VALUE"` inside an object literal (e.g. a config block:
# `const config = { apiUrl: "https://...", ... }`). Deliberately does not
# try to track which object NAME belongs to — a flat name->value map is
# enough for the call-site resolution below, and false-positive collisions
# on a common key name (e.g. two different "url" keys) just mean we try an
# extra candidate value, not a wrong one — the existing dedup + prescore
# filter downstream cleans that up the same way it does for every other
# discovery source.
_OBJ_KEY_RE = re.compile(
    r"""([A-Za-z_$][\w$]{0,60})\s*:\s*[`'"]([^`'"]{1,300})[`'"]""",
)

# Call sites where the URL argument is a bare identifier instead of a
# string literal — mirrors crawler.py's _JS_ENDPOINT_PATTERNS shape but
# captures the VARIABLE NAME, not a literal.
_CALL_WITH_VAR_RE = [
    re.compile(r"""fetch\(\s*([A-Za-z_$][\w$.]{0,60})\s*[,)]"""),
    re.compile(r"""axios(?:\.\w+)?\(\s*([A-Za-z_$][\w$.]{0,60})\s*[,)]"""),
    re.compile(r"""\.open\(\s*[`'"]\w+[`'"]\s*,\s*([A-Za-z_$][\w$.]{0,60})\s*[,)]"""),
    re.compile(r"""url\s*:\s*([A-Za-z_$][\w$.]{0,60})\s*[,}]"""),
]

# `IDENT + "literal"` string concatenation — the single most common
# real-world pattern for a base-URL variable + relative-path literal.
_VAR_PLUS_LITERAL_RE = re.compile(
    r"""([A-Za-z_$][\w$]{0,60})\s*\+\s*[`'"]([^`'"]{1,200})[`'"]""",
)

_JS_KEYWORDS = frozenset({
    "true", "false", "null", "undefined", "this", "window", "document",
})


def build_var_url_map(text: str) -> dict[str, str]:
    """
    NAME -> string-literal-value, from both simple assignments and object
    literal keys in the same script body. Values that don't look even
    vaguely URL/path-shaped (no leading '/' or scheme) are kept anyway —
    a base-URL variable like `API_BASE = "https://api.x.com"` still needs
    to resolve for the `IDENT + "/path"` concatenation case below, even
    though the base value alone has no path component to flag as SSRF-relevant.
    """
    var_map: dict[str, str] = {}
    for pattern in (_VAR_ASSIGN_RE, _OBJ_KEY_RE):
        for m in pattern.finditer(text):
            name, value = m.group(1), m.group(2)
            if name in _JS_KEYWORDS or not value:
                continue
            var_map.setdefault(name, value)
    return var_map


def resolve_call_arg_vars(text: str, var_map: dict[str, str]) -> set[str]:
    """
    Find call sites whose URL argument is a bare identifier (or a simple
    `obj.prop` access — matched but only the bare-name part is looked up,
    which is enough for the common `cfg.apiUrl` shape where `apiUrl` was
    also captured as an object-literal key by build_var_url_map) and
    resolve it through var_map.
    """
    found: set[str] = set()
    for pattern in _CALL_WITH_VAR_RE:
        for m in pattern.finditer(text):
            ident = m.group(1).split(".")[-1]  # `cfg.apiUrl` -> `apiUrl`
            if ident in var_map:
                found.add(var_map[ident])
    return found


def resolve_concatenations(text: str, var_map: dict[str, str]) -> set[str]:
    """
    `API_BASE + "/proxy"` -> "https://api.x.com/proxy", when API_BASE is a
    known variable. Single-hop concatenation only (no chained
    `a + b + c` resolution) — deliberately simple, catches the dominant
    real-world shape without becoming a JS parser.
    """
    found: set[str] = set()
    for m in _VAR_PLUS_LITERAL_RE.finditer(text):
        ident, literal = m.group(1), m.group(2)
        base = var_map.get(ident)
        if not base:
            continue
        if base.startswith(("http://", "https://")) or base.startswith("/"):
            found.add(base.rstrip("/") + "/" + literal.lstrip("/"))
    return found


# ---------------------------------------------------------------------------
# Framework-specific route-table extraction
# ---------------------------------------------------------------------------

# React Router / Vue Router style config arrays:
#   { path: "/admin/:id", component: ... }
_ROUTE_PATH_RE = re.compile(
    r"""\bpath\s*:\s*[`'"](\/[a-zA-Z0-9_\-/:.]{1,120})[`'"]""",
)


def extract_js_routes(text: str) -> set[str]:
    """
    Route DEFINITIONS, not fetch calls — a client-side router entry like
    `/admin/settings` is not itself an HTTP endpoint, but many apps expose
    a same-path server API under `/api` + the route, or the routed
    component immediately fires a fetch to a sibling API path once
    mounted. Recording these as discovery candidates (never as fuzzable
    endpoints on their own — same "let the existing filter decide"
    principle as every other JS-sourced signal here) gives Phase 0's
    keyword inference more surface to work with on SPAs where the server
    HTML never links to /admin/... anywhere.
    """
    return {m.group(1) for m in _ROUTE_PATH_RE.finditer(text)}


# Next.js build manifest: `self.__BUILD_MANIFEST = {"/":[...], "/foo":[...]}`
# or the sortedPages array variant. Route keys are quoted path strings
# immediately following one of these two markers.
_NEXTJS_MANIFEST_MARKER_RE = re.compile(
    r"""(?:__BUILD_MANIFEST\s*=|sortedPages\s*[:=])\s*(\{.{0,4000}?\}|\[.{0,4000}?\])""",
    re.DOTALL,
)
_NEXTJS_ROUTE_RE = re.compile(r"""[`'"](\/[a-zA-Z0-9_\-/[\]]{0,120})[`'"]""")


def extract_nextjs_manifest_routes(text: str) -> set[str]:
    routes: set[str] = set()
    for blob_match in _NEXTJS_MANIFEST_MARKER_RE.finditer(text):
        blob = blob_match.group(1)
        for route_match in _NEXTJS_ROUTE_RE.finditer(blob):
            routes.add(route_match.group(1))
    return routes


# ---------------------------------------------------------------------------
# Single entry point used by crawler.py
# ---------------------------------------------------------------------------

def enrich(text: str) -> set[str]:
    """
    Returns a set of raw path/URL strings recovered via variable
    resolution and framework route-table parsing. Caller (crawler.py's
    `_analyze_js_text`) is responsible for resolving these against the
    page base URL and running them through the same scope/skip checks
    every other discovered URL goes through — this module never fetches
    or resolves anything itself, it only reads the text it's given.
    """
    var_map = build_var_url_map(text)
    found: set[str] = set()
    found |= resolve_call_arg_vars(text, var_map)
    found |= resolve_concatenations(text, var_map)
    found |= extract_js_routes(text)
    found |= extract_nextjs_manifest_routes(text)
    return found
