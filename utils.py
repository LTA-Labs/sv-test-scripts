from email.utils import parseaddr

from config import DEFAULT_EMAIL_TEST_DOMAIN


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
