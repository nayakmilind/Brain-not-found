import logging
from collections import Counter

import pytest
from hypothesis import given
from hypothesis import strategies as st

from app.pipeline.detectors.false_positive_filter import is_relevant_context
from app.pipeline.detectors.masking import mask_value
from app.pipeline.detectors.presidio_engine import detect

_BENCHMARK = (
    ("Email: morgan@example.test", "EMAIL_ADDRESS", "morgan@example.test"),
    ("Contact address: rowan@example.invalid", "EMAIL_ADDRESS", "rowan@example.invalid"),
    ("Reach me at quinn@demo.example", "EMAIL_ADDRESS", "quinn@demo.example"),
    ("Call me at +1 202 555 0142", "PHONE_NUMBER", "+1 202 555 0142"),
    ("My phone is +1 303 555 0118", "PHONE_NUMBER", "+1 303 555 0118"),
    ("Telephone: +1 415 555 0199", "PHONE_NUMBER", "+1 415 555 0199"),
    ("Postal code: 98101", "US_ZIP_CODE", "98101"),
    ("My ZIP is 10001", "US_ZIP_CODE", "10001"),
    ("Mailing zip code: 60601", "US_ZIP_CODE", "60601"),
    ("Date of birth: 04/12/1991", "DOB_DATE", "04/12/1991"),
    ("Birthday is 11-23-1988", "DOB_DATE", "11-23-1988"),
    ("DOB: 02.08.1995", "DOB_DATE", "02.08.1995"),
    ("Social handle: @morgan_example", "SOCIAL_HANDLE", "@morgan_example"),
    ("Profile username @rowan_north", "SOCIAL_HANDLE", "@rowan_north"),
    ("My social profile: @quinn_synthetic", "SOCIAL_HANDLE", "@quinn_synthetic"),
    ("Name: Morgan Example", "PERSON", "Morgan Example"),
    ("Name: Rowan Northstar", "PERSON", "Rowan Northstar"),
    ("Name: Quinn Sampleton", "PERSON", "Quinn Sampleton"),
)


@pytest.mark.parametrize(
    ("value", "entity_type"),
    [
        ("morgan@example.test", "EMAIL_ADDRESS"),
        ("+1 202 555 0142", "PHONE_NUMBER"),
        ("Morgan Example", "PERSON"),
        ("98101", "US_ZIP_CODE"),
        ("a", "PERSON"),
        ("", "PERSON"),
    ],
)
def test_masked_preview_never_contains_full_value(value: str, entity_type: str) -> None:
    preview = mask_value(value, entity_type)

    assert preview
    assert preview != value
    assert not value or value not in preview


@given(st.text(min_size=1, max_size=128))
def test_masking_property_never_returns_the_unmasked_value(value: str) -> None:
    assert mask_value(value, "PERSON") != value


def test_context_classifier_suppresses_numeric_false_positive() -> None:
    assert is_relevant_context("my postal code is <value>")
    assert not is_relevant_context("invoice total <value>")


def test_detection_does_not_log_raw_pii(caplog: pytest.LogCaptureFixture) -> None:
    email = "synthetic.persona@example.test"
    caplog.set_level(logging.DEBUG)

    detect(f"Email: {email}")

    assert email not in caplog.text


def test_synthetic_detector_benchmark_exceeds_f1_target(capsys: pytest.CaptureFixture[str]) -> None:
    expected = Counter((entity_type, value) for _, entity_type, value in _BENCHMARK)
    predicted: Counter[tuple[str, str]] = Counter()
    for text, _, _ in _BENCHMARK:
        predicted.update((span.entity_type, text[span.start : span.end]) for span in detect(text))

    scores: dict[str, tuple[float, float, float]] = {}
    print("type | precision | recall | F1")
    for entity_type in sorted({kind for kind, _ in expected}):
        true_positive = sum(
            min(expected[key], predicted[key]) for key in expected if key[0] == entity_type
        )
        expected_count = sum(count for (kind, _), count in expected.items() if kind == entity_type)
        predicted_count = sum(
            count for (kind, _), count in predicted.items() if kind == entity_type
        )
        precision = true_positive / predicted_count if predicted_count else 0.0
        recall = true_positive / expected_count if expected_count else 0.0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
        scores[entity_type] = precision, recall, f1
        print(f"{entity_type} | {precision:.2f} | {recall:.2f} | {f1:.2f}")

    assert all(f1 >= 0.85 for _, _, f1 in scores.values()), capsys.readouterr().out
