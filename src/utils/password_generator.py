import string
import random
import threading
import itertools
import datetime
from typing import List, Optional, Tuple

def generate_password(length: int = 12, min_length: Optional[int] = None, max_length: Optional[int] = None,
                     use_uppercase: bool = True, use_lowercase: bool = True,
                     use_numbers: bool = True, use_special: bool = True) -> str:
    """Generate a random password with the specified characteristics."""
    # Validate length
    if not (6 <= length <= 24):
        raise ValueError("Password length must be between 6 and 24 characters")

    # Ensure at least one character type is selected
    if not (use_uppercase or use_lowercase or use_numbers or use_special):
        raise ValueError("At least one character type must be selected")

    # Define character sets based on user preferences
    chars = ""
    if use_uppercase:
        chars += string.ascii_uppercase
    if use_lowercase:
        chars += string.ascii_lowercase
    if use_numbers:
        chars += string.digits
    if use_special:
        chars += string.punctuation

    # Generate password
    password = ''.join(random.choice(chars) for _ in range(length))

    # Ensure password includes at least one character from each selected character set
    while True:
        has_uppercase = any(c in string.ascii_uppercase for c in password) if use_uppercase else True
        has_lowercase = any(c in string.ascii_lowercase for c in password) if use_lowercase else True
        has_number = any(c in string.digits for c in password) if use_numbers else True
        has_special = any(c in string.punctuation for c in password) if use_special else True

        if has_uppercase and has_lowercase and has_number and has_special:
            break

        # If a required character type is missing, regenerate password
        password = ''.join(random.choice(chars) for _ in range(length))

    return password

def generate_passwords_in_parallel(count: int, length: int, min_length: Optional[int] = None,
                                 max_length: Optional[int] = None, use_uppercase: bool = True,
                                 use_lowercase: bool = True, use_numbers: bool = True,
                                 use_special: bool = True) -> List[str]:
    """Generate multiple passwords in parallel using a fixed length"""
    passwords = []
    for _ in range(count):
        # Use fixed length if only length is provided
        current_length = length

        # Or use random length within range if min_length and max_length are provided
        if min_length is not None and max_length is not None:
            current_length = random.randint(min_length, max_length)

        passwords.append(generate_password(
            length=current_length,
            use_uppercase=use_uppercase,
            use_lowercase=use_lowercase,
            use_numbers=use_numbers,
            use_special=use_special
        ))
    return passwords

def estimate_password_count(length: int, charset_size: int) -> int:
    """Calculate the number of possible passwords with given parameters"""
    return charset_size ** length

def calculate_password_strength(password: str) -> Tuple[int, str]:
    """Calculate the strength of a password and return a score and description"""
    score = 0
    feedback = []

    # Length check
    if len(password) >= 12:
        score += 2
        feedback.append("Good length")
    elif len(password) >= 8:
        score += 1
        feedback.append("Acceptable length")
    else:
        feedback.append("Too short")

    # Character variety checks
    if any(c.isupper() for c in password):
        score += 1
        feedback.append("Contains uppercase")
    if any(c.islower() for c in password):
        score += 1
        feedback.append("Contains lowercase")
    if any(c.isdigit() for c in password):
        score += 1
        feedback.append("Contains numbers")
    if any(c in string.punctuation for c in password):
        score += 1
        feedback.append("Contains special characters")

    # Entropy check
    charset_size = 0
    if any(c.isupper() for c in password):
        charset_size += 26
    if any(c.islower() for c in password):
        charset_size += 26
    if any(c.isdigit() for c in password):
        charset_size += 10
    if any(c in string.punctuation for c in password):
        charset_size += 32

    entropy = len(password) * (charset_size ** 0.5)
    if entropy > 100:
        score += 2
        feedback.append("High entropy")
    elif entropy > 50:
        score += 1
        feedback.append("Moderate entropy")

    # Final strength assessment
    if score >= 7:
        strength = "Very Strong"
    elif score >= 5:
        strength = "Strong"
    elif score >= 3:
        strength = "Moderate"
    else:
        strength = "Weak"

    return score, f"{strength} ({', '.join(feedback)})" 