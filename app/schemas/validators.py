import re

def normalize_name(value):
    if isinstance(value, str):
        return value.strip()
    return value

def validate_name(value: str) -> str:
    # Unicode letters and spaces only
    if not re.fullmatch(
        r"[^\W\d_]+(?: +[^\W\d_]+)*",
        value,
        flags=re.UNICODE,
    ):
        raise ValueError("Name must contain letters and spaces only")

    return value

def validate_password(value: str) -> str:
    if not re.search(r"[a-z]", value):
        raise ValueError("Password must include a lowercase letter")

    if not re.search(r"[A-Z]", value):
        raise ValueError("Password must include an uppercase letter")

    if not re.search(r"\d", value):
        raise ValueError("Password must include a number")

    if not re.search(r"[^A-Za-z0-9\s]", value):
        raise ValueError("Password must include a special character")

    return value