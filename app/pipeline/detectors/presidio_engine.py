import logging
from dataclasses import dataclass
from datetime import datetime
from functools import lru_cache
from threading import Lock

from presidio_analyzer import AnalyzerEngine, RecognizerResult
from presidio_analyzer.nlp_engine import NlpEngineProvider

from app.pipeline.detectors.custom_recognizers import build_custom_recognizers
from app.pipeline.detectors.false_positive_filter import is_relevant_context

_SUPPORTED_ENTITIES = [
    "CREDIT_CARD",
    "DATE_TIME",
    "DOB_DATE",
    "EMAIL_ADDRESS",
    "IBAN_CODE",
    "LOCATION",
    "ORGANIZATION",
    "PERSON",
    "PHONE_NUMBER",
    "SOCIAL_HANDLE",
    "US_SSN",
    "US_ZIP_CODE",
]
_NER_ENTITIES = {"LOCATION", "ORGANIZATION", "PERSON"}
_CLASSIFIED_ENTITIES = {"DOB_DATE", "SOCIAL_HANDLE", "US_ZIP_CODE"}
_DETECTION_LOCK = Lock()
_NON_PII_NER_TOKENS = {
    "birthday",
    "contact",
    "dob",
    "email",
    "handle",
    "name",
    "phone",
    "postal",
    "profile",
    "social",
    "telephone",
    "username",
    "zip",
}


@dataclass(frozen=True)
class DetectedSpan:
    entity_type: str
    start: int
    end: int
    detector: str
    confidence: float
    evidence_class: str
    context_flags: tuple[str, ...]


@lru_cache(maxsize=1)
def _analyzer() -> AnalyzerEngine:
    logging.getLogger("presidio-analyzer").setLevel(logging.WARNING)
    provider = NlpEngineProvider(
        nlp_configuration={
            "nlp_engine_name": "spacy",
            "models": [{"lang_code": "en", "model_name": "en_core_web_sm"}],
        }
    )
    engine = AnalyzerEngine(
        nlp_engine=provider.create_engine(),
        supported_languages=["en"],
    )
    for recognizer in build_custom_recognizers():
        engine.registry.add_recognizer(recognizer)
    return engine


def detect(text: str) -> list[DetectedSpan]:
    if not text.strip():
        return []
    with _DETECTION_LOCK:
        results = _analyzer().analyze(
            text=text,
            language="en",
            entities=_SUPPORTED_ENTITIES,
            score_threshold=0.3,
        )
    candidates = [
        detection for result in results if (detection := _to_detection(text, result)) is not None
    ]
    return _deduplicate(candidates)


def _to_detection(text: str, result: RecognizerResult) -> DetectedSpan | None:
    value = text[result.start : result.end]
    if not value.strip():
        return None

    entity_type = result.entity_type
    context = _context_window(text, result.start, result.end)
    if entity_type in _NER_ENTITIES and (
        "@" in value
        or not any(character.isalpha() for character in value)
        or value.casefold() in _NON_PII_NER_TOKENS
    ):
        return None
    if entity_type == "DATE_TIME" and value.isdigit() and len(value) in {5, 9}:
        return None
    if entity_type in _CLASSIFIED_ENTITIES and not is_relevant_context(context):
        return None
    if entity_type == "DOB_DATE" and not _is_calendar_date(value):
        return None

    flags = _context_flags(context)
    if entity_type in _NER_ENTITIES:
        detector = "spacy_ner"
        evidence_class = "INFERRED"
    elif entity_type in _CLASSIFIED_ENTITIES:
        detector = "custom_regex+context_classifier"
        evidence_class = "VERIFIED" if entity_type == "SOCIAL_HANDLE" else "INFERRED"
    else:
        detector = "presidio"
        evidence_class = (
            "VERIFIED"
            if entity_type
            in {
                "CREDIT_CARD",
                "EMAIL_ADDRESS",
                "PHONE_NUMBER",
                "US_SSN",
            }
            else "UNCERTAIN"
        )

    return DetectedSpan(
        entity_type=entity_type,
        start=result.start,
        end=result.end,
        detector=detector,
        confidence=min(max(float(result.score), 0.0), 1.0),
        evidence_class=evidence_class,
        context_flags=flags,
    )


def _context_window(text: str, start: int, end: int) -> str:
    prefix = text[max(0, start - 64) : start]
    suffix = text[end : min(len(text), end + 64)]
    return f"{prefix} <value> {suffix}".casefold()


def _context_flags(context: str) -> tuple[str, ...]:
    flags: list[str] = []
    if any(word in context for word in ("contact", "email", "phone", "call")):
        flags.append("CONTACT_CONTEXT")
    if any(word in context for word in ("address", "postal", "zip code")):
        flags.append("ADDRESS_CONTEXT")
    if any(word in context for word in ("birth", "birthday", "dob")):
        flags.append("BIRTH_CONTEXT")
    if any(word in context for word in ("profile", "handle", "username", "social")):
        flags.append("PROFILE_CONTEXT")
    return tuple(flags)


def _is_calendar_date(value: str) -> bool:
    for date_format in ("%m/%d/%Y", "%m-%d-%Y", "%m.%d.%Y"):
        try:
            datetime.strptime(value, date_format)
            return True
        except ValueError:
            continue
    return False


def _deduplicate(candidates: list[DetectedSpan]) -> list[DetectedSpan]:
    spans = {(item.start, item.end, item.entity_type) for item in candidates}
    best: dict[tuple[int, int, str], DetectedSpan] = {}
    for candidate in candidates:
        same_span = (candidate.start, candidate.end)
        if candidate.entity_type in _NER_ENTITIES and (*same_span, "EMAIL_ADDRESS") in spans:
            continue
        if candidate.entity_type == "ORGANIZATION" and (*same_span, "PERSON") in spans:
            continue
        if candidate.entity_type == "DATE_TIME" and (*same_span, "DOB_DATE") in spans:
            continue
        if candidate.entity_type == "PHONE_NUMBER" and (
            (*same_span, "DOB_DATE") in spans or (*same_span, "DATE_TIME") in spans
        ):
            continue
        key = (candidate.start, candidate.end, candidate.entity_type)
        current = best.get(key)
        if current is None or candidate.confidence > current.confidence:
            best[key] = candidate
    return sorted(best.values(), key=lambda item: (item.start, item.end, item.entity_type))
