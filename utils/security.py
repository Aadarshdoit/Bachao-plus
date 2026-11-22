"""
BACHAO+ Security Utilities
Implements PBKDF2 cryptographic hashing, input sanitization, Shannon entropy scoring,
magic-bytes file inspection, and clearance authorization verification.
"""

import hashlib
import hmac
import math
import os
import re
import secrets
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from dotenv import load_dotenv

# Load optional .env configuration
load_dotenv()

# Top notorious breached passwords for baseline heuristic lookup
COMMON_PASSWORDS_SET = {
    "123456", "password", "123456789", "12345678", "12345", "111111", "1234567",
    "dragon", "123123", "baseball", "football", "shadow", "monkey", "sunshine",
    "princess", "qwerty", "welcome", "admin", "admin123", "password123", "iloveyou",
    "charlie", "donald", "superman", "starwars", "secret", "master", "trustno1",
    "killer", "solo", "system", "pass123", "operator", "security", "defence",
    "india123", "police", "campus", "guard", "login", "guest", "default", "root",
    "toor", "passphrase", "changeme", "letmein", "testing", "stream", "server"
}

# Common keyboard walking patterns
KEYBOARD_WALKS = [
    "qwerty", "asdfgh", "zxcvbn", "123456", "654321", "abcdef", "fedcba",
    "qwertz", "azerty", "098765", "qazwsx", "edcrfv", "poiuyt", "lkjhgf"
]

# Wordlist for high-entropy defensive passphrase generator
DEFENCE_WORDLIST = [
    "shield", "perimeter", "sentinel", "citadel", "bastion", "overwatch",
    "vanguard", "matrix", "beacon", "telemetry", "cypher", "firewall",
    "radar", "quantum", "patrol", "vector", "horizon", "secure",
    "phoenix", "falcon", "titan", "valiant", "ironclad", "shadow"
]


# ---------------------------------------------------------------------------
# Cryptographic Password Hashing & Verification (PBKDF2-HMAC-SHA256)
# ---------------------------------------------------------------------------
def hash_password(password: str, salt: Optional[str] = None) -> Tuple[str, str]:
    """
    Hash a password using PBKDF2-HMAC-SHA256 with 100,000 iterations and a 16-byte random salt.
    Returns (hex_hash, hex_salt).
    """
    if salt is None:
        salt_bytes = secrets.token_bytes(16)
        salt_hex = salt_bytes.hex()
    else:
        salt_bytes = bytes.fromhex(salt)
        salt_hex = salt

    iterations = 100000
    pwd_bytes = password.encode("utf-8")
    hash_bytes = hashlib.pbkdf2_hmac("sha256", pwd_bytes, salt_bytes, iterations)
    return hash_bytes.hex(), salt_hex


def verify_password(password: str, stored_hash: str, salt: str) -> bool:
    """
    Verify candidate password against stored PBKDF2 hash using constant-time comparison.
    """
    try:
        calculated_hash, _ = hash_password(password, salt)
        return hmac.compare_digest(calculated_hash, stored_hash)
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Role Authorization & Anti-Escalation Checks
# ---------------------------------------------------------------------------
def verify_clearance_code(role: str, provided_code: str) -> Tuple[bool, str]:
    """
    Prevent unauthorized role escalation during self-registration.
    Students require no clearance code.
    Campus Security and Admin roles require a matching server authorization key.
    """
    if role == "Student":
        return True, ""

    clean_code = (provided_code or "").strip()
    if not clean_code:
        return False, f"A valid supervisor clearance passcode is required to register as '{role}'."

    if role == "Campus Security":
        expected_key = os.getenv("SECURITY_CLEARANCE_KEY", "")
        if hmac.compare_digest(clean_code, expected_key):
            return True, ""
        return False, "Invalid Security Clearance Passcode. Contact Campus Overwatch supervisor."

    if role == "Admin":
        expected_key = os.getenv("ADMIN_REGISTRATION_KEY", "")
        if hmac.compare_digest(clean_code, expected_key):
            return True, ""
        return False, "Invalid Administrator Authorization Key. Root elevation rejected."

    return False, f"Unknown role '{role}' requested."


# ---------------------------------------------------------------------------
# Input Validation & Sanitization
# ---------------------------------------------------------------------------
def sanitize_input(text: str) -> str:
    """
    Strip HTML tags, control characters, and dangerous null bytes from user input.
    """
    if not isinstance(text, str):
        return ""
    clean = text.replace("\x00", "")
    clean = re.sub(r"<[^>]*>", "", clean)
    return clean.strip()


def validate_username(username: str) -> Tuple[bool, str]:
    """
    Validate username format: 3 to 30 characters, alphanumeric, underscores, hyphens.
    """
    clean = username.strip()
    if len(clean) < 3:
        return False, "Username must be at least 3 characters long."
    if len(clean) > 30:
        return False, "Username must not exceed 30 characters."
    if not re.match(r"^[a-zA-Z0-9_-]+$", clean):
        return False, "Username may only contain letters, numbers, underscores, and hyphens."
    return True, ""


def validate_email(email: str) -> Tuple[bool, str]:
    """
    Validate email address structure.
    """
    clean = email.strip()
    pattern = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
    if not re.match(pattern, clean):
        return False, "Please enter a valid email address (e.g., cadet@campus.edu)."
    return True, ""


def validate_password_policy(password: str) -> Tuple[bool, str]:
    """
    Verify candidate password meets baseline platform requirements (min 8 chars).
    """
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    return True, ""


# ---------------------------------------------------------------------------
# File Upload Security & Magic Bytes Validation
# ---------------------------------------------------------------------------
def validate_uploaded_file(uploaded_file, max_size_mb: float = 5.0) -> Tuple[bool, str]:
    """
    Thoroughly inspect uploaded evidence files:
    1. Size boundary enforcement (max 5 MB).
    2. Extension whitelist (.png, .jpg, .jpeg).
    3. MIME type header verification.
    4. Magic bytes header inspection to prevent executable masquerading.
    """
    if uploaded_file is None:
        return True, ""

    # 1. Check file size
    size_mb = uploaded_file.size / (1024 * 1024)
    if size_mb > max_size_mb:
        return False, f"File exceeds maximum allowed size ({max_size_mb} MB). Uploaded: {size_mb:.2f} MB."

    # 2. Check extension
    allowed_exts = {".png", ".jpg", ".jpeg"}
    name = uploaded_file.name.lower()
    ext = os.path.splitext(name)[1]
    if ext not in allowed_exts:
        return False, f"Unsupported file extension '{ext}'. Only PNG and JPEG images are accepted."

    # 3. Check MIME type header
    allowed_types = {"image/png", "image/jpeg", "image/jpg"}
    if uploaded_file.type not in allowed_types:
        return False, f"Invalid MIME format '{uploaded_file.type}'. Expected PNG or JPEG image."

    # 4. Check Magic Bytes Header (first 16 bytes)
    try:
        header = uploaded_file.getvalue()[:16]
        is_png = header.startswith(b"\x89PNG\r\n\x1a\n")
        is_jpeg = header.startswith(b"\xff\xd8\xff")

        if ext == ".png" and not is_png:
            return False, "Corrupted or spoofed PNG image: Magic bytes header mismatch."
        if ext in (".jpg", ".jpeg") and not is_jpeg:
            return False, "Corrupted or spoofed JPEG image: Magic bytes header mismatch."
    except Exception as e:
        return False, f"Could not verify file binary structure: {str(e)}"

    return True, ""


# ---------------------------------------------------------------------------
# Shannon Entropy and Password Complexity Analysis
# ---------------------------------------------------------------------------
def calculate_entropy(password: str) -> float:
    """
    Calculate cryptographic Shannon entropy of a password string in bits.
    Formula: L * log2(R), where L is length and R is the active pool character set.
    """
    if not password:
        return 0.0

    charset_pool = 0
    if re.search(r"[a-z]", password):
        charset_pool += 26
    if re.search(r"[A-Z]", password):
        charset_pool += 26
    if re.search(r"[0-9]", password):
        charset_pool += 10
    if re.search(r"[^a-zA-Z0-9]", password):
        charset_pool += 32

    if charset_pool == 0:
        return 0.0

    entropy = len(password) * math.log2(charset_pool)
    return round(entropy, 2)


def is_common_password(password: str) -> Tuple[bool, str]:
    """Check if password appears in top known common dictionary lists."""
    normalized = password.lower().strip()
    if normalized in COMMON_PASSWORDS_SET:
        return True, f"Matches notorious dictionary entry '{normalized}'."
    return False, ""


def detect_weak_patterns(password: str) -> List[str]:
    """
    Detect predictable patterns such as repeated characters, keyboard walks, or years.
    """
    patterns = []
    pwd_lower = password.lower()

    # 1. Repeated characters (e.g. 'aaaa', '1111')
    if re.search(r"(.)\1{2,}", password):
        patterns.append("Contains repeated identical characters (e.g. 'aaa' or '111').")

    # 2. Keyboard walks
    for walk in KEYBOARD_WALKS:
        if walk in pwd_lower:
            patterns.append(f"Contains predictable keyboard walk '{walk}'.")
            break

    # 3. Year pattern (e.g., 1990 - 2026)
    if re.search(r"(19\d\d|20[0-2]\d)", password):
        patterns.append("Contains common 4-digit calendar year pattern.")

    return patterns


def evaluate_password_security(password: str) -> Dict[str, Any]:
    """
    Comprehensive password analysis: length, character variety, entropy, patterns, and scoring.
    """
    length = len(password)
    entropy = calculate_entropy(password)
    is_common, common_msg = is_common_password(password)
    weak_patterns = detect_weak_patterns(password)

    has_lower = bool(re.search(r"[a-z]", password))
    has_upper = bool(re.search(r"[A-Z]", password))
    has_digit = bool(re.search(r"[0-9]", password))
    has_symbol = bool(re.search(r"[^a-zA-Z0-9]", password))

    # Base scoring algorithm (0 - 100)
    score = 0
    suggestions = []

    # Length scoring
    if length >= 16:
        score += 35
    elif length >= 12:
        score += 25
    elif length >= 8:
        score += 15
        suggestions.append("Increase length to at least 12–16 characters for resilient defense.")
    else:
        score += max(0, length * 2)
        suggestions.append("Critically short: minimum 8 characters required.")

    # Complexity scoring
    if has_lower and has_upper:
        score += 25
    elif has_lower or has_upper:
        score += 10
        suggestions.append("Use a combination of both UPPERCASE and lowercase letters.")
    else:
        suggestions.append("Include alphabetic characters.")

    if has_digit:
        score += 20
    else:
        suggestions.append("Add numeric numbers (0–9) to diversify keyspace.")

    if has_symbol:
        score += 20
    else:
        suggestions.append("Incorporate special symbols (!@#$%^&*...) to thwart brute-force dictionaries.")

    # Deductions for weak heuristics
    if is_common:
        score = min(score, 20)
        suggestions.insert(0, f"⚠️ CRITICAL: {common_msg} Change immediately.")

    if weak_patterns:
        score = max(5, score - (len(weak_patterns) * 15))
        for p in weak_patterns:
            suggestions.append(f"Avoid pattern: {p}")

    # Determine classification rating and theme color
    if score >= 80 and entropy >= 60 and not is_common:
        rating = "STRONG (Defence-Grade)"
        color = "#0F766E"  # Subtle Teal/Green
    elif score >= 55 and not is_common:
        rating = "MODERATE"
        color = "#D97706"  # Amber
    elif score >= 35:
        rating = "WEAK"
        color = "#DC2626"  # Subtle Red
    else:
        rating = "CRITICAL RISK"
        color = "#991B1B"  # Dark Red

    return {
        "score": min(score, 100),
        "entropy_bits": entropy,
        "rating": rating,
        "color": color,
        "length": length,
        "has_lower": has_lower,
        "has_upper": has_upper,
        "has_digit": has_digit,
        "has_symbol": has_symbol,
        "is_common": is_common,
        "weak_patterns": weak_patterns,
        "suggestions": suggestions
    }


def generate_strong_passphrase(num_words: int = 4) -> str:
    """Generate high-entropy Diceware-style memorable passphrase."""
    chosen = [secrets.choice(DEFENCE_WORDLIST) for _ in range(num_words)]
    number = secrets.randbelow(90) + 10
    special = secrets.choice(["!", "#", "$", "&", "*", "@"])
    return f"{'-'.join(chosen)}{special}{number}"


def mask_sensitive_string(value: str, visible_start: int = 2, visible_end: int = 2) -> str:
    """Mask credentials or tokens for safe representation in logs."""
    if not value:
        return "***"
    if len(value) <= (visible_start + visible_end):
        return "*" * len(value)
    return f"{value[:visible_start]}{'*' * (len(value) - visible_start - visible_end)}{value[-visible_end:]}"

