"""Authorized lab hash inventory and hash-format identification helpers."""

import re
from pathlib import Path


SHADOW_ALGORITHMS = {
    "1": "MD5-crypt",
    "2a": "Blowfish bcrypt",
    "2b": "Blowfish bcrypt",
    "2y": "Blowfish bcrypt",
    "5": "SHA-256-crypt",
    "6": "SHA-512-crypt",
    "y": "yescrypt",
}


def identify_hash(value: str) -> str:
    value = value.strip()
    if value.startswith("$"):
        parts = value.split("$")
        if len(parts) > 2:
            return SHADOW_ALGORITHMS.get(parts[1], f"Modular crypt format ${parts[1]}$")
    if re.fullmatch(r"[a-fA-F0-9]{32}", value):
        return "NTLM or MD5"
    if re.fullmatch(r"[a-fA-F0-9]{40}", value):
        return "SHA-1"
    if re.fullmatch(r"[a-fA-F0-9]{64}", value):
        return "SHA-256"
    if re.fullmatch(r"[a-fA-F0-9]{128}", value):
        return "SHA-512"
    return "Unknown"


def parse_shadow(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        raise FileNotFoundError(f"Shadow file not found: {path}")

    rows: list[dict[str, str]] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line or line.startswith("#"):
            continue
        parts = line.split(":")
        if len(parts) < 2:
            continue
        username, hash_value = parts[0], parts[1]
        rows.append(
            {
                "source": str(path),
                "username": username,
                "hash": hash_value,
                "algorithm": identify_hash(hash_value),
                "locked_or_empty": str(hash_value in {"", "!", "*"} or hash_value.startswith("!")),
            }
        )
    return rows


def inspect_windows_hives(sam: Path, system: Path) -> list[dict[str, str]]:
    return [
        {
            "source": str(sam),
            "type": "SAM hive",
            "status": "present" if sam.exists() else "missing",
            "note": "Offline hive detected. Use only in an authorized lab with a forensic parser.",
        },
        {
            "source": str(system),
            "type": "SYSTEM hive",
            "status": "present" if system.exists() else "missing",
            "note": "SYSTEM hive pairs with SAM for authorized offline Windows hash inventory.",
        },
    ]
