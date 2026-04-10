"""Password hashing utilities using bcrypt via passlib.

Usage:
    from app.auth.password import hash_password, verify_password

    hashed = hash_password("my-secure-password")
    ok = verify_password("my-secure-password", hashed)
"""

from passlib.context import CryptContext

MIN_PASSWORD_LENGTH = 12

_ctx = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto",
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
    return _ctx.hash(plaintext)


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
    return _ctx.verify(plaintext, hashed)
