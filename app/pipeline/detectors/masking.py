import re


def mask_value(value: str, entity_type: str) -> str:
    stripped = value.strip()
    if not stripped:
        return "***"

    normalized_type = entity_type.upper()
    if normalized_type == "EMAIL_ADDRESS" and "@" in stripped:
        local, domain = stripped.rsplit("@", 1)
        domain_parts = domain.split(".")
        masked_local = _mask_token(local, visible=1)
        if len(domain_parts) > 1:
            domain_name = _mask_token(domain_parts[0], visible=1)
            masked_domain = ".".join([domain_name, *domain_parts[1:]])
        else:
            masked_domain = _mask_token(domain, visible=1)
        return _ensure_masked(stripped, f"{masked_local}@{masked_domain}"[:256])

    if normalized_type in {
        "CREDIT_CARD",
        "PHONE_NUMBER",
        "US_SSN",
        "US_ZIP_CODE",
    }:
        digits = "".join(character for character in stripped if character.isdigit())
        visible_digits = digits[-4:] if len(digits) > 4 else digits[-2:]
        return _ensure_masked(stripped, f"***{visible_digits}")

    masked = " ".join(_mask_token(token, visible=1) for token in stripped.split())
    return _ensure_masked(stripped, masked[:256] or "***")


def _mask_token(token: str, *, visible: int) -> str:
    if len(token) <= visible:
        return "*" * max(len(token), 3)
    return token[:visible] + "*" * (len(token) - visible)


def _ensure_masked(value: str, preview: str) -> str:
    if preview == value:
        return "*" * (len(value) + 1)
    return preview


def normalize_value(value: str, entity_type: str) -> str:
    normalized_type = entity_type.upper()
    compact = " ".join(value.split()).casefold()
    if normalized_type in {"PHONE_NUMBER", "CREDIT_CARD", "US_SSN", "US_ZIP_CODE"}:
        return re.sub(r"\D", "", compact)
    return compact
