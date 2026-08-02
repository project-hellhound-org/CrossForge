import json
from pathlib import Path
from typing import Any

_CACHE: dict[str, Any] = {}
_PAYLOADS_DIR = Path(__file__).parent / "payloads"

def load_payload_json(filename: str) -> Any:
    """Loads a JSON file from the core/payloads directory, caching the result in memory."""
    if filename not in _CACHE:
        path = _PAYLOADS_DIR / filename
        _CACHE[filename] = json.loads(path.read_text(encoding="utf-8"))
    return _CACHE[filename]
