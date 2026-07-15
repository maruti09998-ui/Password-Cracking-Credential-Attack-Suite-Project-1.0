"""
Dictionary Generator Module

Generates custom wordlists based on user input, common patterns, and mutations.
"""
import itertools
import re

COMMON_PASSWORDS = {
    "123456", "123456789", "password", "qwerty", "abc123", 
    "111111", "password1", "admin", "letmein", "welcome", "iloveyou"
}

KEYBOARD_PATTERNS = [
    "qwerty", "asdfgh", "zxcvbn", "123456", "1qaz2wsx", "qazwsx",
]

LEET_MAP = str.maketrans({"a": "4", "e": "3", "i": "1", "o": "0", "s": "5", "t": "7"})

def unique(items):
    seen = set()
    output = []
    for item in items:
        if item and item not in seen:
            seen.add(item)
            output.append(item)
    return output

def mutate_word(word: str, max_suffix: int = 99) -> set[str]:
    variants = {word, word.lower(), word.upper(), word.capitalize(), word.translate(LEET_MAP)}
    base = set(variants)
    for suffix in range(max_suffix + 1):
        for item in base:
            variants.add(f"{item}{suffix}")
            variants.add(f"{item}{suffix:02d}")
    variants.update(f"{item}!" for item in base)
    variants.update(f"{item}@" for item in base)
    return variants

def generate_wordlist(names: list[str], dobs: list[str], extra: list[str], include_common: bool) -> list[str]:
    seeds = names + extra + KEYBOARD_PATTERNS
    if include_common:
        seeds += sorted(COMMON_PASSWORDS)

    dob_tokens = []
    for dob in dobs:
        parts = re.findall(r"\d+", dob)
        dob_tokens.extend(parts)
        if len(parts) >= 3:
            day, month, year = parts[0], parts[1], parts[2]
            dob_tokens.extend([day + month, month + day, year, year[-2:], day + month + year])

    candidates = []
    for seed in seeds:
        candidates.extend(mutate_word(seed))
        for token in dob_tokens:
            candidates.extend([seed + token, seed.capitalize() + token, seed.translate(LEET_MAP) + token])

    for left, right in itertools.permutations(names[:6], 2):
        candidates.extend([left + right, left.capitalize() + right.capitalize()])

    return unique(candidates)
