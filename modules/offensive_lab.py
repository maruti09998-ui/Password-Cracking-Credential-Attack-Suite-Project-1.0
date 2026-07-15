"""Controlled red-team lab exercises for password-audit demonstrations.

These helpers operate only on local files supplied by the user. They do not
connect to services, dump live credentials, or bypass operating-system access
controls.
"""

from __future__ import annotations

import hashlib
import itertools
import string
from pathlib import Path


SUPPORTED_HASHES = {"md5", "sha1", "sha256", "sha512"}


def hash_text(value: str, algorithm: str) -> str:
    algorithm = algorithm.lower()
    if algorithm not in SUPPORTED_HASHES:
        raise ValueError(f"Unsupported algorithm: {algorithm}. Use one of {sorted(SUPPORTED_HASHES)}.")
    return hashlib.new(algorithm, value.encode("utf-8")).hexdigest()


def load_hash_targets(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        raise FileNotFoundError(f"Hash target file not found: {path}")

    targets: list[dict[str, str]] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), start=1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        if ":" in line:
            label, hash_value = line.split(":", 1)
        else:
            label, hash_value = f"target_{line_number}", line

        targets.append({"label": label.strip(), "hash": hash_value.strip().lower()})
    return targets


def crack_dictionary(hash_file: Path, wordlist: Path, algorithm: str, max_words: int | None = None) -> dict:
    targets = load_hash_targets(hash_file)
    remaining = {target["hash"]: target["label"] for target in targets}
    cracked: list[dict[str, str | int]] = []
    attempts = 0

    for candidate in wordlist.read_text(encoding="utf-8", errors="replace").splitlines():
        candidate = candidate.strip()
        if not candidate:
            continue
        attempts += 1
        digest = hash_text(candidate, algorithm)
        if digest in remaining:
            cracked.append(
                {
                    "label": remaining.pop(digest),
                    "hash": digest,
                    "password": candidate,
                    "attempt": attempts,
                    "method": "dictionary",
                }
            )
        if not remaining or (max_words and attempts >= max_words):
            break

    return {
        "mode": "offline_dictionary_lab",
        "algorithm": algorithm.lower(),
        "targets": len(targets),
        "attempts": attempts,
        "cracked_count": len(cracked),
        "cracked": cracked,
        "uncracked": [{"label": label, "hash": hash_value} for hash_value, label in remaining.items()],
    }


def charset_from_mask(mask: str) -> list[str]:
    groups = {
        "?l": string.ascii_lowercase,
        "?u": string.ascii_uppercase,
        "?d": string.digits,
        "?s": string.punctuation,
    }
    output: list[str] = []
    i = 0
    while i < len(mask):
        token = mask[i : i + 2]
        if token in groups:
            output.append(groups[token])
            i += 2
        else:
            output.append(mask[i])
            i += 1
    return output


def crack_mask(hash_file: Path, mask: str, algorithm: str, max_attempts: int = 100_000) -> dict:
    targets = load_hash_targets(hash_file)
    remaining = {target["hash"]: target["label"] for target in targets}
    cracked: list[dict[str, str | int]] = []
    attempts = 0
    charsets = charset_from_mask(mask)

    for combo in itertools.product(*charsets):
        candidate = "".join(combo)
        attempts += 1
        digest = hash_text(candidate, algorithm)
        if digest in remaining:
            cracked.append(
                {
                    "label": remaining.pop(digest),
                    "hash": digest,
                    "password": candidate,
                    "attempt": attempts,
                    "method": f"mask:{mask}",
                }
            )
        if not remaining or attempts >= max_attempts:
            break

    return {
        "mode": "offline_mask_lab",
        "algorithm": algorithm.lower(),
        "mask": mask,
        "targets": len(targets),
        "attempts": attempts,
        "attempt_limit": max_attempts,
        "cracked_count": len(cracked),
        "cracked": cracked,
        "uncracked": [{"label": label, "hash": hash_value} for hash_value, label in remaining.items()],
    }


def simulate_credential_replay(credentials: Path, allowed_users: Path) -> dict:
    """Replay a candidate credential list against a local allow-list fixture."""
    allowed = {}
    for line in allowed_users.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip() or line.startswith("#") or ":" not in line:
            continue
        username, password = line.split(":", 1)
        allowed[username.strip()] = password.strip()

    attempts = 0
    successes: list[dict[str, str | int]] = []
    for line in credentials.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip() or line.startswith("#") or ":" not in line:
            continue
        username, password = line.split(":", 1)
        attempts += 1
        username = username.strip()
        password = password.strip()
        if allowed.get(username) == password:
            successes.append({"username": username, "password": password, "attempt": attempts})

    return {
        "mode": "local_credential_replay_lab",
        "attempts": attempts,
        "success_count": len(successes),
        "successes": successes,
        "note": "Local fixture simulation only; no network authentication was attempted.",
    }
