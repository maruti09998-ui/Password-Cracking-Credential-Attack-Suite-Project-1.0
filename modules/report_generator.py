"""
Report Generator Module

Generates structured JSON reports from the analysis results.
"""
import json
from dataclasses import asdict
from datetime import datetime
from pathlib import Path

from .password_analyzer import StrengthResult

def write_report(
    path: Path,
    weak_passwords: list[StrengthResult],
    simulations: list[dict] | None = None,
    hashes: list[dict] | None = None,
    cracking: list[dict] | None = None,
    replay: list[dict] | None = None,
) -> None:
    simulations = simulations or []
    hashes = hashes or []
    cracking = cracking or []
    replay = replay or []
    severity_counts = {
        "high": sum(1 for p in weak_passwords if p.severity == "high"),
        "medium": sum(1 for p in weak_passwords if p.severity == "medium"),
        "low": sum(1 for p in weak_passwords if p.severity == "low"),
    }
    payload = {
        "generated_at": datetime.utcnow().isoformat(timespec="seconds") + "Z",
        "scope": "Authorized lab and defensive password-audit use only.",
        "analysis_results": [asdict(item) for item in weak_passwords],
        "simulation_results": simulations,
        "hash_inventory": hashes,
        "red_team_lab_results": {
            "cracking": cracking,
            "credential_replay": replay,
        },
        "summary": {
            "total_analyzed": len(weak_passwords),
            "weak_passwords_count": sum(1 for p in weak_passwords if p.weaknesses),
            "severity_counts": severity_counts,
            "hash_records": len(hashes),
            "simulation_records": len(simulations),
            "cracking_records": len(cracking),
            "credential_replay_records": len(replay),
        },
        "risk_summary": [
            "Dictionary and keyboard-pattern matches indicate elevated credential-stuffing risk.",
            "Short or low-entropy passwords reduce brute-force resistance.",
            "Cracked lab hashes show why leaked hash exposure requires password resets and stronger storage.",
            "Successful replay fixtures show why MFA, lockout, and reused-password controls matter.",
        ],
        "recommended_policies": [
            "Minimum 14 characters for user passwords; longer for privileged accounts.",
            "Block common, leaked, organization-specific, and keyboard-pattern passwords.",
            "Prefer MFA and rate limiting over relying on password complexity alone.",
            "Monitor repeated authentication failures and credential stuffing indicators.",
            "Store passwords with modern salted slow hashes such as yescrypt, bcrypt, scrypt, or Argon2."
        ]
    }
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
