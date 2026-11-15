from presidio_analyzer import Pattern, PatternRecognizer


def build_custom_recognizers() -> list[PatternRecognizer]:
    return [
        PatternRecognizer(
            supported_entity="EMAIL_ADDRESS",
            patterns=[
                Pattern(
                    name="email_address",
                    regex=(
                        r"(?<![\w.+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\."
                        r"[A-Za-z]{2,}(?![\w.-])"
                    ),
                    score=0.95,
                )
            ],
            context=["email", "contact", "reach", "mail"],
        ),
        PatternRecognizer(
            supported_entity="US_ZIP_CODE",
            patterns=[
                Pattern(
                    name="us_zip_code",
                    regex=r"(?<!\d)\d{5}(?:-\d{4})?(?!\d)",
                    score=0.35,
                )
            ],
            context=["zip", "zip code", "postal code", "address"],
        ),
        PatternRecognizer(
            supported_entity="DOB_DATE",
            patterns=[
                Pattern(
                    name="date_of_birth",
                    regex=(
                        r"(?<!\d)(?:0?[1-9]|1[0-2])[/.-]"
                        r"(?:0?[1-9]|[12]\d|3[01])[/.-](?:19|20)\d{2}(?!\d)"
                    ),
                    score=0.35,
                )
            ],
            context=["dob", "date of birth", "birthday", "born"],
        ),
        PatternRecognizer(
            supported_entity="SOCIAL_HANDLE",
            patterns=[
                Pattern(
                    name="social_handle",
                    regex=r"(?<![\w@])@[A-Za-z0-9_][A-Za-z0-9_.]{1,29}",
                    score=0.7,
                )
            ],
            context=["profile", "handle", "username", "social"],
        ),
        PatternRecognizer(
            supported_entity="PERSON",
            patterns=[
                Pattern(
                    name="name_after_label",
                    regex=r"(?<=Name: )[A-Z][a-z]{2,}\s+[A-Z][a-z]{2,}",
                    score=0.65,
                )
            ],
            context=["name", "person", "profile owner"],
        ),
    ]
