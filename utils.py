import random
import string
from email.utils import parseaddr
from typing import List, Tuple

from config import DEFAULT_EMAIL_TEST_DOMAIN


def generate_users(count: int, prefix: str = "user", password_length: int = 8) -> List[Tuple[str, str]]:
    if password_length < 8:
        raise ValueError("Password length must be at least 8 characters")

    users = []
    for i in range(1, count + 1):
        username = f"{prefix}{i}{DEFAULT_EMAIL_TEST_DOMAIN}"

        # Ensure password contains at least one capital letter, one digit, and one special character
        uppercase = random.choice(string.ascii_uppercase)
        digit = random.choice(string.digits)
        special = random.choice("!@#$%^&*()-_=+.")

        # Fill the rest of the password with random characters
        remaining_length = password_length - 3
        other_chars = ''.join(random.choices(
            string.ascii_letters + string.digits + "!@#$%^&*()-_=+.",
            k=remaining_length
        ))

        # Combine all parts and shuffle to randomize
        password = list(uppercase + digit + special + other_chars)
        random.shuffle(password)
        password = ''.join(password)

        users.append((username, password))

    return users


def validate_username(username: str, check_sv_prefix=False) -> str | None:
    """Simple validator that checks username format"""
    if not username:
        return
    if check_sv_prefix and not username.startswith("sv-"):
        username = 'sv-' + username

    name, address = parseaddr(username)
    if '@' in address:
        if '.' in address.split('@')[-1] and '.' not in [address[0], address[-1]]:
            return username
        return  # Username is in an invalid email format
    return username + DEFAULT_EMAIL_TEST_DOMAIN
