# Risk scoring and estimates

## Risk score

The score is an estimate based only on the user's supplied, eligible sources.
It is not proof of identity exposure or total safety. `score-v1` is persisted
with each scan's score so the factors used by that report remain inspectable.

Each finding has four factors in the range 0–1:

- **S (sensitivity):** the M5 sensitivity level divided by 5.
- **V (visibility):** a verified, fetchable URL uses 1.0. Pasted text, files,
  platform exports, and unknown source kinds use 0.7. URL indexing is not
  checked; the response labels that visibility assumption. The value 0.7 is a
  conservative proxy for self-declared content whose publication status is
  unknown.
- **C (context):** starts at 0.6; adds 0.2 for contact/address/birth/profile
  context, 0.1 for a title or metadata segment, and 0.1 for visible text, capped
  at 1.0. Hidden-only text is capped at 0.5. Finding recency is not available
  in the current data model and is not included.
- **K (confidence):** detector confidence multiplied by the evidence factor:
  VERIFIED = 1.0, INFERRED = 0.8, UNCERTAIN = 0.5.

```text
finding_risk = S × V × C × K
base_risk = 1 − Π(1 − finding_risk_i)
raw_risk = min(1, base_risk × graph.combination_multiplier)
risk_score = round(raw_risk × 100)
privacy_score = 100 − risk_score
```

The graph multiplier is bounded to 1.0–1.6 and is itself a heuristic based on
distinct entity-kind pairs and entities recurring across sources. It is not a
probability. A truncated graph is marked in the score response; omitted graph
edges may make its combination multiplier incomplete, so the score uses the
maximum 1.6 multiplier conservatively whenever graph construction is truncated.
Risk bands use risk score thresholds: LOW <25, MODERATE <50, HIGH <75,
otherwise CRITICAL.

The overall confidence value is the mean of finding K factors; it is 0.0 when
there are no findings. A 100 privacy score with no findings is still only a
result about the supplied sources and is not proof that the person is safe.

## What-if simulation

`POST /v1/scans/{scan_id}/simulate` accepts up to 500 finding IDs to remove.
The service validates that every ID belongs to the authenticated user's scan,
then recomputes the score and bounded graph in memory. It does not rescan
sources or persist the simulated result.

## Re-identification uniqueness

The uniqueness endpoint uses the explicitly approved type-only proxy in
[`app/data/uniqueness_lookup.yaml`](../app/data/uniqueness_lookup.yaml). It
starts from an illustrative cohort of one million and multiplies generic
selectivity assumptions for the distinct detected finding types. It does not
look up or compare actual names, locations, colleges, birth years, or people.
The result is always labelled VERY_LOW confidence and must not be interpreted
as a population statistic or an estimate for a specific individual. This
proxy is not the city/college public lookup originally described in the
architecture.

## Defensive attacker view

The attacker-view panel uses fixed rules over detected types to label phishing
personalisation, SIM-swap/KYC-answer, and impersonation exposure as LOW, MEDIUM,
or HIGH. It returns masked evidence and defensive fixes only; it performs no
real-world action and does not provide operational attack instructions.
