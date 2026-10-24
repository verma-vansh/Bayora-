"""Attack library loader."""
from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

LIB = Path(__file__).resolve().parent.parent / "attacks" / "library.json"
CATEGORIES = ("prompt_injection", "jailbreak", "data_leakage", "obfuscation", "benign")


@lru_cache
def load_attacks() -> list[dict]:
    return json.loads(LIB.read_text(encoding="utf-8"))
