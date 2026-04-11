"""Password hashing utilities using bcrypt directly.

Usage:
    from app.auth.password import hash_password, verify_password

    hashed = hash_password("my-secure-password")
    ok = verify_password("my-secure-password", hashed)
"""

import re

import bcrypt

MIN_PASSWORD_LENGTH = 12
_SYMBOL_RE = re.compile(r"[!@#$%^&*()\-_=+\[\]{}|;:'\",.<>?/\\`~]")


def validate_password_complexity(plaintext: str) -> None:
    """Enforce password complexity rules.

    Rules: min 12 chars, ≥1 digit, ≥1 symbol.

    Args:
        plaintext: Password to validate.

    Raises:
        ValueError: On any rule violation.
    """
    if len(plaintext) < MIN_PASSWORD_LENGTH:
        raise ValueError(
            f"Password too short: minimum "
            f"{MIN_PASSWORD_LENGTH} characters required"
        )
    if not any(c.isdigit() for c in plaintext):
        raise ValueError(
            "Password must contain at least one digit"
        )
    if not _SYMBOL_RE.search(plaintext):
        raise ValueError(
            "Password must contain at least one "
            "symbol (!@#$%^&* etc.)"
        )


def hash_password(plaintext: str) -> str:
    """Hash a plaintext password with bcrypt.

    Args:
        plaintext: The password to hash.

    Returns:
        A bcrypt hash string (e.g. "$2b$12$...").

    Raises:
        ValueError: If the password is shorter than
            MIN_PASSWORD_LENGTH characters.
    """
    if len(plaintext) < MIN_PASSWORD_LENGTH:
        raise ValueError(
            f"Password too short: minimum "
            f"{MIN_PASSWORD_LENGTH} characters required"
        )
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(
        plaintext.encode(), salt
    ).decode()


def verify_password(
    plaintext: str, hashed: str
) -> bool:
    """Verify a plaintext password against a hash.

    Args:
        plaintext: The candidate password.
        hashed: The stored bcrypt hash.

    Returns:
        True if the password matches, False otherwise.
        Returns False for empty plaintext without
        calling the hash function.
    """
    if not plaintext:
        return False
    return bcrypt.checkpw(
        plaintext.encode(), hashed.encode()
    )
