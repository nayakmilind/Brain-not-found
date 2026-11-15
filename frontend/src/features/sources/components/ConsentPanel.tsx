import { useState } from "react";
import type { ConsentVersion } from "../api";
import { ApiErrorNotice } from "./ApiErrorNotice";

type ConsentPanelProps = {
  consent: ConsentVersion;
  isPending: boolean;
  error: unknown;
  onAccept: () => void;
};

const scopeLabels: Record<string, string> = {
  assess_only_my_own_sources: "Assess only your own sources",
  never_request_platform_credentials: "Never request platform credentials",
  scores_are_estimates_not_safety_guarantees:
    "Scores are estimates, not safety guarantees",
};

export function ConsentPanel({ consent, isPending, error, onAccept }: ConsentPanelProps) {
  const [accepted, setAccepted] = useState(false);

  return (
    <section className="consent-card" aria-labelledby="consent-title">
      <div className="consent-heading">
        <p className="eyebrow">YOUR CHOICE, CLEARLY EXPLAINED</p>
        <h1 id="consent-title">Before you add a source</h1>
        <p className="page-lede">
          Review this versioned consent before submitting anything. You can revoke consent
          later; that blocks new source submissions and ownership checks.
        </p>
      </div>

      <div className="consent-version">
        Consent version <strong>{consent.version}</strong>
      </div>

      <ul className="consent-statements">
        {consent.statements.map((statement) => (
          <li key={statement}>
            <span className="consent-check" aria-hidden="true">
              ✓
            </span>
            <span>{statement}</span>
          </li>
        ))}
      </ul>

      <ul className="consent-scope" aria-label="Consent scope">
        {Object.entries(consent.scope)
          .filter(([, enabled]) => enabled)
          .map(([key]) => (
            <li key={key}>{scopeLabels[key] ?? key.replaceAll("_", " ")}</li>
          ))}
      </ul>

      <label className="consent-accept">
        <input
          type="checkbox"
          checked={accepted}
          onChange={(event) => setAccepted(event.currentTarget.checked)}
        />
        <span>
          I have read and agree to consent version <strong>{consent.version}</strong>.
        </span>
      </label>

      <ApiErrorNotice
        error={error}
        fallback="Consent could not be saved. Check your connection and try again."
      />

      <button
        className="primary-button consent-submit"
        type="button"
        disabled={!accepted || isPending}
        onClick={onAccept}
      >
        {isPending ? "Saving your consent…" : "Accept and continue"}
        <span aria-hidden="true">→</span>
      </button>
      <p className="consent-footnote">
        Your acceptance is recorded with this version. No source is added or fetched by
        accepting.
      </p>
    </section>
  );
}
