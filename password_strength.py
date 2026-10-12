"""A small, dependency-free password strength analyzer."""

from __future__ import annotations

import argparse
import getpass
import re
import sys
from dataclasses import dataclass


_COMMON_PASSWORDS = {
    "123456",
    "123456789",
    "12345678",
    "12345",
    "password",
    "password1",
    "qwerty",
    "qwerty123",
    "abc123",
    "111111",
    "123123",
    "admin",
    "letmein",
    "welcome",
    "iloveyou",
}


@dataclass(frozen=True)
class StrengthResult:
    """Strength score and actionable feedback for a password."""

    score: int
    label: str
    feedback: tuple[str, ...]


def _has_sequential_run(password: str, minimum: int = 4) -> bool:
    """Return whether the password contains an ascending or descending ASCII run."""
    password = password.translate(str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz"))
    run_length = 1
    direction = 0
    for previous, current in zip(password, password[1:]):
        difference = ord(current) - ord(previous)
        step = difference if difference in (-1, 1) else 0
        if step and step == direction:
            run_length += 1
        elif step:
            direction = step
            run_length = 2
        else:
            direction = 0
            run_length = 1
        if run_length >= minimum:
            return True
    return False


def analyze_password(password: str) -> StrengthResult:
    """Score a password from 0 to 100 and return suggestions for improvement.

    This is a heuristic, offline estimate, not a guarantee against guessing.
    """
    if not password:
        return StrengthResult(0, "Very weak", ("Use a password that is at least 12 characters long.",))

    score = 0
    feedback: list[str] = []

    if len(password) < 8:
        feedback.append("Use at least 8 characters; 12 or more is better.")
    elif len(password) < 12:
        score += 20
        feedback.append("Make it at least 12 characters long.")
    elif len(password) < 16:
        score += 35
        feedback.append("Consider using 16 or more characters.")
    elif len(password) < 20:
        score += 45
    else:
        score += 55

    classes = (
        any(character.islower() for character in password),
        any(character.isupper() for character in password),
        any(character.isdigit() for character in password),
        any(not character.isalnum() for character in password),
    )
    score += sum(classes) * 10
    if sum(classes) < 3:
        feedback.append("Mix at least three of lowercase, uppercase, numbers, and symbols.")

    score += min(5, len(set(password)))

    normalized = password.casefold()
    if normalized in _COMMON_PASSWORDS:
        score -= 50
        feedback.append("Avoid common passwords and predictable variations.")
    if re.search(r"(.)\1{3,}", password):
        score -= 20
        feedback.append("Avoid repeating the same character several times.")
    if _has_sequential_run(password):
        score -= 20
        feedback.append("Avoid sequences such as 'abcd' or '4321'.")

    score = max(0, min(100, score))
    if score < 30:
        label = "Very weak"
    elif score < 50:
        label = "Weak"
    elif score < 70:
        label = "Fair"
    elif score < 90:
        label = "Strong"
    else:
        label = "Very strong"

    if not feedback:
        feedback.append("Looks good. A unique passphrase is even better.")
    return StrengthResult(score, label, tuple(feedback))


def main() -> int:
    parser = argparse.ArgumentParser(description="Estimate password strength locally.")
    parser.parse_args()

    if sys.stdin.isatty():
        password = getpass.getpass("Password (input hidden): ")
    else:
        password = sys.stdin.readline().rstrip("\r\n")

    result = analyze_password(password)
    print(f"Strength: {result.label} ({result.score}/100)")
    for item in result.feedback:
        print(f"- {item}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
