"""Brute-force feasibility simulator for defensive planning."""

import math
import string


def charset_for_mode(mode: list[str]) -> str:
    chars = ""
    if "lower" in mode:
        chars += string.ascii_lowercase
    if "upper" in mode:
        chars += string.ascii_uppercase
    if "digits" in mode:
        chars += string.digits
    if "symbols" in mode:
        chars += string.punctuation
    return chars or string.ascii_lowercase


def human_time(seconds: float) -> str:
    if math.isinf(seconds):
        return "infinite"

    units = [("year", 31_536_000), ("day", 86_400), ("hour", 3_600), ("minute", 60)]
    for name, size in units:
        if seconds >= size:
            value = seconds / size
            suffix = "" if value == 1 else "s"
            return f"{value:.2f} {name}{suffix}"
    return f"{seconds:.2f} seconds"


def simulate_bruteforce(
    mode: list[str],
    min_length: int,
    max_length: int,
    guesses_per_second: float,
) -> dict[str, float | int | str]:
    if min_length < 1:
        raise ValueError("min_length must be at least 1")
    if max_length < min_length:
        raise ValueError("max_length must be greater than or equal to min_length")
    if guesses_per_second <= 0:
        raise ValueError("guesses_per_second must be greater than 0")

    chars = charset_for_mode(mode)
    keyspace = sum(len(chars) ** length for length in range(min_length, max_length + 1))
    seconds = keyspace / guesses_per_second
    return {
        "mode": ",".join(mode),
        "charset_size": len(chars),
        "min_length": min_length,
        "max_length": max_length,
        "keyspace": keyspace,
        "guesses_per_second": guesses_per_second,
        "estimated_seconds": round(seconds, 2),
        "estimated_time": human_time(seconds),
    }
