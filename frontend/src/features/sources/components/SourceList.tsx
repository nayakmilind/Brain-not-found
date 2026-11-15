import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { ApiError } from "../../../api/errors";
import { queryKeys } from "../../../api/queryKeys";
import {
  createOwnershipChallenge,
  deleteSource,
  verifyOwnership,
  type OwnershipChallenge,
  type OwnershipMethod,
  type SourceRecord,
} from "../api";
import { ApiErrorNotice } from "./ApiErrorNotice";

type SourceListProps = {
  sources: SourceRecord[];
  offset: number;
  hasNextPage: boolean;
  onPageChange: (offset: number) => void;
  onConsentRequired: () => void;
};

const ownershipLabels: Record<string, string> = {
  UNVERIFIED: "Ownership not verified",
  PENDING: "Verification in progress",
  VERIFIED: "Ownership verified",
  SELF_DECLARED: "Self-declared",
};

function OwnershipWizard({
  source,
  onConsentRequired,
  onClose,
}: {
  source: SourceRecord;
  onConsentRequired: () => void;
  onClose: () => void;
}) {
  const queryClient = useQueryClient();
  const [method, setMethod] = useState<OwnershipMethod>("BIO_TOKEN");
  const [email, setEmail] = useState("");
  const [proof, setProof] = useState("");
  const [challenge, setChallenge] = useState<OwnershipChallenge | null>(null);
  const [verified, setVerified] = useState(false);

  const challengeMutation = useMutation({
    mutationFn: () =>
      createOwnershipChallenge(
        source.id,
        method,
        method === "EMAIL_OTP" ? email.trim() : undefined,
      ),
    onSuccess: async (createdChallenge) => {
      if (createdChallenge.ownership_status === "VERIFIED") {
        setVerified(true);
        await queryClient.invalidateQueries({ queryKey: queryKeys.sources.all });
        return;
      }
      setChallenge(createdChallenge);
    },
    onError: (error) => {
      if (error instanceof ApiError && error.status === 403) {
        onConsentRequired();
      }
    },
  });

  const verifyMutation = useMutation({
    mutationFn: () => {
      if (!challenge?.challenge_id) {
        throw new Error("The challenge ID is unavailable. Create a new challenge.");
      }
      return verifyOwnership(
        source.id,
        challenge.challenge_id,
        method === "EMAIL_OTP" ? proof.trim() : null,
      );
    },
    onSuccess: async () => {
      setVerified(true);
      setChallenge(null);
      setProof("");
      await queryClient.invalidateQueries({ queryKey: queryKeys.sources.all });
    },
    onError: (error) => {
      if (error instanceof ApiError && error.status === 403) {
        onConsentRequired();
      }
    },
  });

  const methods: { value: OwnershipMethod; label: string; detail: string }[] = [
    {
      value: "BIO_TOKEN",
      label: "Profile bio token",
      detail: "Place a temporary token in the public profile bio.",
    },
    {
      value: "META_TAG",
      label: "Website meta tag",
      detail: "Add a temporary verification meta tag to the page.",
    },
    {
      value: "DNS_TXT",
      label: "DNS TXT record",
      detail: "Add a temporary TXT record to the domain.",
    },
    {
      value: "EMAIL_OTP",
      label: "Domain email code",
      detail: "Receive a one-time code at an email address on the same domain.",
    },
  ];

  function chooseMethod(value: OwnershipMethod) {
    setMethod(value);
    setChallenge(null);
    setProof("");
    challengeMutation.reset();
    verifyMutation.reset();
  }

  if (verified) {
    return (
      <div className="ownership-wizard" role="status">
        <p className="success-message">
          Ownership verified. The source list has been updated.
        </p>
        <button className="quiet-button" onClick={onClose} type="button">
          Close
        </button>
      </div>
    );
  }

  return (
    <section className="ownership-wizard" aria-labelledby={`verify-${source.id}`}>
      <div className="ownership-wizard-heading">
        <div>
          <p className="eyebrow">VERIFY YOUR URL</p>
          <h3 id={`verify-${source.id}`}>Choose an ownership check</h3>
          <p>
            These checks only confirm control. They never bypass platform protections.
          </p>
        </div>
        <button className="quiet-button" onClick={onClose} type="button">
          Close
        </button>
      </div>

      {source.ownership_status === "PENDING" && !challenge && (
        <p className="source-field-note" role="status">
          A challenge is already active, but its token is only shown when it is created.
          If you no longer have its instructions, wait for the 15-minute challenge to
          expire before starting another.
        </p>
      )}

      {!challenge && source.ownership_status !== "PENDING" && (
        <>
          <div
            className="ownership-methods"
            role="radiogroup"
            aria-label="Verification method"
          >
            {methods.map((option) => (
              <label className="ownership-method" key={option.value}>
                <input
                  checked={method === option.value}
                  name={`ownership-method-${source.id}`}
                  onChange={() => chooseMethod(option.value)}
                  type="radio"
                  value={option.value}
                />
                <span>
                  <strong>{option.label}</strong>
                  <small>{option.detail}</small>
                </span>
              </label>
            ))}
          </div>

          {method === "EMAIL_OTP" && (
            <label className="source-field ownership-email">
              <span>Domain email address</span>
              <input
                autoComplete="email"
                onChange={(event) => setEmail(event.currentTarget.value)}
                placeholder="you@your-domain.example"
                required
                type="email"
                value={email}
              />
              <small>
                The address domain must match the website domain or a parent domain.
              </small>
            </label>
          )}

          <ApiErrorNotice
            error={challengeMutation.error}
            fallback="The ownership challenge could not be created. Check your connection and try again."
          />
          <button
            className="primary-button source-submit"
            disabled={
              challengeMutation.isPending ||
              (method === "EMAIL_OTP" && email.trim().length === 0)
            }
            onClick={() => challengeMutation.mutate()}
            type="button"
          >
            {challengeMutation.isPending ? "Creating challenge…" : "Create challenge"}
            <span aria-hidden="true">→</span>
          </button>
        </>
      )}

      {challenge && (
        <div className="challenge-instructions">
          <p className="challenge-expiry">
            {challenge.expires_at
              ? `Expires ${new Date(challenge.expires_at).toLocaleString()}.`
              : "This challenge is ready."}
          </p>
          <p>{challenge.instructions}</p>
          {challenge.token && (
            <div className="challenge-token">
              <span>Temporary verification token</span>
              <code>{challenge.token}</code>
            </div>
          )}
          {method === "EMAIL_OTP" && (
            <label className="source-field ownership-email">
              <span>Six-digit code</span>
              <input
                autoComplete="one-time-code"
                inputMode="numeric"
                maxLength={6}
                onChange={(event) => setProof(event.currentTarget.value)}
                pattern="[0-9]{6}"
                required
                value={proof}
              />
            </label>
          )}
          <ApiErrorNotice
            error={verifyMutation.error}
            fallback="We could not verify that proof. Confirm it is in place and try again."
          />
          <button
            className="primary-button source-submit"
            disabled={
              verifyMutation.isPending ||
              (method === "EMAIL_OTP" && !/^\d{6}$/.test(proof))
            }
            onClick={() => verifyMutation.mutate()}
            type="button"
          >
            {verifyMutation.isPending ? "Checking ownership…" : "Verify ownership"}
            <span aria-hidden="true">→</span>
          </button>
        </div>
      )}
    </section>
  );
}

export function SourceList({
  sources,
  offset,
  hasNextPage,
  onPageChange,
  onConsentRequired,
}: SourceListProps) {
  const queryClient = useQueryClient();
  const [expandedSource, setExpandedSource] = useState<string | null>(null);
  const [confirmingSource, setConfirmingSource] = useState<string | null>(null);
  const deleteMutation = useMutation({
    mutationFn: deleteSource,
    onSuccess: () => {
      setConfirmingSource(null);
      void queryClient.invalidateQueries({ queryKey: queryKeys.sources.all });
    },
    onError: (error) => {
      if (error instanceof ApiError && error.status === 403) {
        onConsentRequired();
      }
    },
  });

  if (sources.length === 0 && offset === 0) {
    return (
      <section className="source-list-card" aria-labelledby="source-list-title">
        <div className="source-list-heading">
          <div>
            <p className="eyebrow">YOUR PRIVATE INVENTORY</p>
            <h2 id="source-list-title">No sources yet</h2>
          </div>
        </div>
        <p className="empty-sources">
          Add only sources you own. URL sources must pass an ownership check before they
          can be scanned.
        </p>
      </section>
    );
  }

  return (
    <section className="source-list-card" aria-labelledby="source-list-title">
      <div className="source-list-heading">
        <div>
          <p className="eyebrow">YOUR PRIVATE INVENTORY</p>
          <h2 id="source-list-title">Sources you added</h2>
        </div>
        <span className="source-count">{sources.length} shown</span>
      </div>

      <ul className="source-list">
        {sources.map((source) => {
          const ownershipLabel =
            ownershipLabels[source.ownership_status] ?? "Status unavailable";
          const isUrl = source.kind === "URL";
          const isExpanded = expandedSource === source.id;
          const isConfirmingDelete = confirmingSource === source.id;

          return (
            <li className="source-list-item" key={source.id}>
              <div className="source-item-main">
                <div className="source-item-icon" aria-hidden="true">
                  {isUrl ? "↗" : "▤"}
                </div>
                <div className="source-item-copy">
                  <strong>{source.label_preview}</strong>
                  <span>
                    {source.kind === "URL"
                      ? "Website URL"
                      : source.kind.replaceAll("_", " ")}
                  </span>
                  <span className="source-status" data-status={source.ownership_status}>
                    {source.status} · {ownershipLabel}
                  </span>
                </div>
                <div className="source-item-actions">
                  {isUrl && source.ownership_status !== "VERIFIED" && (
                    <button
                      className="quiet-button"
                      onClick={() => setExpandedSource(isExpanded ? null : source.id)}
                      type="button"
                    >
                      {isExpanded ? "Hide verification" : "Verify ownership"}
                    </button>
                  )}
                  <button
                    className="text-button"
                    onClick={() =>
                      setConfirmingSource(isConfirmingDelete ? null : source.id)
                    }
                    type="button"
                  >
                    Remove
                  </button>
                </div>
              </div>

              {isConfirmingDelete && (
                <div className="delete-confirmation" role="group">
                  <p>
                    Remove this source? Its source data and related scan data will be
                    deleted.
                  </p>
                  <button
                    className="quiet-button"
                    disabled={deleteMutation.isPending}
                    onClick={() => setConfirmingSource(null)}
                    type="button"
                  >
                    Keep source
                  </button>
                  <button
                    className="danger-button"
                    disabled={deleteMutation.isPending}
                    onClick={() => deleteMutation.mutate(source.id)}
                    type="button"
                  >
                    {deleteMutation.isPending ? "Removing…" : "Remove source"}
                  </button>
                </div>
              )}

              {isExpanded && isUrl && (
                <OwnershipWizard
                  key={source.id}
                  onClose={() => setExpandedSource(null)}
                  onConsentRequired={onConsentRequired}
                  source={source}
                />
              )}
            </li>
          );
        })}
      </ul>

      <ApiErrorNotice
        error={deleteMutation.error}
        fallback="The source could not be removed. Check your connection and try again."
      />
      {(offset > 0 || hasNextPage) && (
        <nav className="source-pagination" aria-label="Source list pages">
          <button
            className="quiet-button"
            disabled={offset === 0}
            onClick={() => onPageChange(Math.max(offset - 100, 0))}
            type="button"
          >
            Previous
          </button>
          <span>
            Showing {offset + 1}–{offset + sources.length}
          </span>
          <button
            className="quiet-button"
            disabled={!hasNextPage}
            onClick={() => onPageChange(offset + 100)}
            type="button"
          >
            Next
          </button>
        </nav>
      )}
    </section>
  );
}
