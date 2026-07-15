"""
Password Strength Analyzer Module

Evaluates passwords for complexity, entropy, and identifies weaknesses.
"""
import math
import re
import string
from collections import Counter
from dataclasses import dataclass

from .dictionary_generator import KEYBOARD_PATTERNS, COMMON_PASSWORDS

@dataclass
class StrengthResult:
    password: str
    length: int
    charset_size: int
    entropy_bits: float
    severity: str
    complexity: dict[str, bool]
    weaknesses: list[str]
    recommendations: list[str]

def rate_severity(entropy: float, weaknesses: list[str], length: int) -> str:
    if entropy < 40 or len(weaknesses) >= 3 or length < 8:
        return "high"
    if entropy < 60 or weaknesses:
        return "medium"
    return "low"

def analyze_password(password: str, dictionary: set[str] | None = None) -> StrengthResult:
    classes = {
        "lowercase": any(c.islower() for c in password),
        "uppercase": any(c.isupper() for c in password),
        "digit": any(c.isdigit() for c in password),
        "symbol": any(c in string.punctuation for c in password),
        "length_12_plus": len(password) >= 12,
    }
    charset = 0
    if classes["lowercase"]:
        charset += 26
    if classes["uppercase"]:
        charset += 26
    if classes["digit"]:
        charset += 10
    if classes["symbol"]:
        charset += len(string.punctuation)
    
    entropy = len(password) * math.log2(max(charset, 1))

    lower = password.lower()
    weaknesses = []
    if lower in COMMON_PASSWORDS or (dictionary and lower in dictionary):
        weaknesses.append("Matches a known dictionary/common password.")
    if len(password) < 12:
        weaknesses.append("Shorter than 12 characters.")
    if re.search(r"(.)\1{2,}", password):
        weaknesses.append("Contains repeated characters.")
    if any(pattern in lower for pattern in KEYBOARD_PATTERNS):
        weaknesses.append("Contains a keyboard pattern.")
    
    counts = Counter(password)
    if counts and max(counts.values()) / len(password) > 0.5:
        weaknesses.append("Dominated by one repeated character.")

    recommendations = []
    if len(password) < 14:
        recommendations.append("Use at least 14 characters or a multi-word passphrase.")
    if not all(classes[k] for k in ["lowercase", "uppercase", "digit", "symbol"]):
        recommendations.append("Mix lowercase, uppercase, digits, and symbols where policy requires complexity.")
    if weaknesses:
        recommendations.append("Avoid names, dates, keyboard walks, and known leaked/common passwords.")
    if entropy < 60:
        recommendations.append("Increase length; length usually improves resistance more reliably than substitutions.")

    entropy_bits = round(entropy, 2)
    severity = rate_severity(entropy_bits, weaknesses, len(password))

    return StrengthResult(
        password, len(password), charset, entropy_bits, severity, classes, weaknesses, recommendations
    )
