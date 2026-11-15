from collections.abc import Sequence
from functools import lru_cache
from typing import Protocol, cast

from sklearn.feature_extraction.text import TfidfVectorizer  # type: ignore[import-untyped]
from sklearn.linear_model import LogisticRegression  # type: ignore[import-untyped]
from sklearn.pipeline import make_pipeline  # type: ignore[import-untyped]

_CONTEXT_EXAMPLES = (
    ("my postal code is <value>", 1),
    ("my zip code is <value>", 1),
    ("send mail to my address <value>", 1),
    ("my date of birth is <value>", 1),
    ("dob <value>", 1),
    ("my birthday is <value>", 1),
    ("my social handle is <value>", 1),
    ("find my profile under <value>", 1),
    ("profile username <value>", 1),
    ("my social profile <value>", 1),
    ("name <value>", 1),
    ("profile owner <value>", 1),
    ("zip <value>", 1),
    ("postal <value>", 1),
    ("invoice total <value>", 0),
    ("the software version is <value>", 0),
    ("reference number <value>", 0),
    ("the sample contains <value>", 0),
    ("published on <value>", 0),
    ("chapter <value> starts here", 0),
)


class _BinaryClassifier(Protocol):
    def fit(self, features: Sequence[str], labels: Sequence[int]) -> object: ...

    def predict_proba(self, features: Sequence[str]) -> Sequence[Sequence[float]]: ...


@lru_cache(maxsize=1)
def _classifier() -> _BinaryClassifier:
    vectorizer = TfidfVectorizer(ngram_range=(1, 2), lowercase=True)
    classifier = cast(
        _BinaryClassifier,
        make_pipeline(
            vectorizer,
            LogisticRegression(random_state=0, max_iter=500),
        ),
    )
    contexts, labels = zip(*_CONTEXT_EXAMPLES, strict=True)
    classifier.fit(contexts, labels)
    return classifier


def is_relevant_context(context: str) -> bool:
    return float(_classifier().predict_proba([context])[0][1]) >= 0.65
