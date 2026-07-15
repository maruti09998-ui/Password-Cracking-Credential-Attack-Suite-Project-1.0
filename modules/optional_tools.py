"""Optional external tool integrations for authorized lab workflows."""

from __future__ import annotations

import importlib.util
import json
import shutil
import subprocess
from pathlib import Path


PORTABLE_TOOL_DIR = Path(r"C:\tmp\password-suite-tools")


def find_tool(name: str) -> str | None:
    path_value = shutil.which(name)
    if path_value:
        return path_value

    portable_candidates = {
        "john": [
            PORTABLE_TOOL_DIR / "john-1.9.0-jumbo-1-win64" / "run" / "john.exe",
        ],
        "hashcat": [
            PORTABLE_TOOL_DIR / "hashcat-7.1.2" / "hashcat.exe",
        ],
    }
    for candidate in portable_candidates.get(name, []):
        if candidate.exists():
            return str(candidate)
    return None


def tool_status() -> dict:
    john = find_tool("john")
    hashcat = find_tool("hashcat")
    return {
        "passlib": {
            "available": importlib.util.find_spec("passlib") is not None,
            "purpose": "Verify/generate Linux crypt-style password hashes.",
        },
        "reg.exe": {
            "available": shutil.which("reg.exe") is not None or shutil.which("reg") is not None,
            "purpose": "Export Windows registry hives in an authorized lab on Windows.",
        },
        "john": {
            "available": john is not None,
            "path": john,
            "purpose": "Run John the Ripper against explicit local hash fixtures.",
        },
        "hashcat": {
            "available": hashcat is not None,
            "path": hashcat,
            "purpose": "Run Hashcat against explicit local hash fixtures.",
        },
    }


def passlib_verify(password: str, hash_value: str) -> dict:
    if importlib.util.find_spec("passlib") is None:
        return {"tool": "passlib", "available": False, "verified": None, "message": "Install passlib first."}

    from passlib.hash import md5_crypt, sha256_crypt, sha512_crypt

    schemes = [sha512_crypt, sha256_crypt, md5_crypt]
    for scheme in schemes:
        try:
            if scheme.identify(hash_value):
                return {
                    "tool": "passlib",
                    "available": True,
                    "scheme": scheme.name,
                    "verified": scheme.verify(password, hash_value),
                }
        except ValueError:
            continue
    return {"tool": "passlib", "available": True, "verified": None, "message": "Unsupported hash format."}


def passlib_hash(password: str, scheme: str) -> dict:
    if importlib.util.find_spec("passlib") is None:
        return {"tool": "passlib", "available": False, "hash": None, "message": "Install passlib first."}

    from passlib.hash import md5_crypt, sha256_crypt, sha512_crypt

    schemes = {
        "md5-crypt": md5_crypt,
        "sha256-crypt": sha256_crypt,
        "sha512-crypt": sha512_crypt,
    }
    if scheme not in schemes:
        raise ValueError(f"Unsupported passlib scheme: {scheme}")
    return {"tool": "passlib", "available": True, "scheme": scheme, "hash": schemes[scheme].hash(password)}


def reg_export_commands(output_dir: Path) -> dict:
    sam = output_dir / "SAM"
    system = output_dir / "SYSTEM"
    return {
        "tool": "reg.exe",
        "available": shutil.which("reg.exe") is not None or shutil.which("reg") is not None,
        "lab_only": True,
        "commands": [
            f'reg.exe save HKLM\\SAM "{sam}" /y',
            f'reg.exe save HKLM\\SYSTEM "{system}" /y',
        ],
        "note": "Run only in an authorized Windows lab with appropriate privileges.",
    }


def export_windows_hives(output_dir: Path) -> dict:
    reg_path = shutil.which("reg.exe") or shutil.which("reg")
    if not reg_path:
        return {"tool": "reg.exe", "available": False, "exported": False, "message": "reg.exe was not found."}

    output_dir.mkdir(parents=True, exist_ok=True)
    results = []
    for hive in ["SAM", "SYSTEM"]:
        destination = output_dir / hive
        command = [reg_path, "save", f"HKLM\\{hive}", str(destination), "/y"]
        completed = subprocess.run(command, capture_output=True, text=True, timeout=60)
        results.append(
            {
                "hive": hive,
                "destination": str(destination),
                "returncode": completed.returncode,
                "stdout": completed.stdout.strip(),
                "stderr": completed.stderr.strip(),
                "success": completed.returncode == 0,
            }
        )
    return {"tool": "reg.exe", "available": True, "exported": all(item["success"] for item in results), "results": results}


def run_john(hash_file: Path, wordlist: Path | None = None, fmt: str | None = None, show: bool = False) -> dict:
    john = find_tool("john")
    if not john:
        return {"tool": "john", "available": False, "message": "John the Ripper was not found on PATH."}

    command = [john]
    if show:
        command.append("--show")
    if fmt:
        command.append(f"--format={fmt}")
    if wordlist:
        command.append(f"--wordlist={wordlist}")
    command.append(str(hash_file))
    completed = subprocess.run(command, capture_output=True, text=True, timeout=300)
    return _external_result("john", command, completed)


def run_hashcat(hash_file: Path, wordlist: Path, mode: int, attack_mode: int = 0, extra_args: list[str] | None = None) -> dict:
    hashcat = find_tool("hashcat")
    if not hashcat:
        return {"tool": "hashcat", "available": False, "message": "Hashcat was not found on PATH."}

    command = [hashcat, "-m", str(mode), "-a", str(attack_mode), str(hash_file), str(wordlist)]
    if extra_args:
        command.extend(extra_args)
    completed = subprocess.run(command, capture_output=True, text=True, timeout=300)
    return _external_result("hashcat", command, completed)


def _external_result(tool: str, command: list[str], completed: subprocess.CompletedProcess[str]) -> dict:
    return {
        "tool": tool,
        "available": True,
        "command": command,
        "returncode": completed.returncode,
        "stdout": completed.stdout[-4000:],
        "stderr": completed.stderr[-4000:],
        "success": completed.returncode == 0,
    }


def write_json(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
