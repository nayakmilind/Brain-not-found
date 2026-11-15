import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { ApiError } from "../../../api/errors";
import { queryKeys } from "../../../api/queryKeys";
import { ApiErrorNotice } from "../components/ApiErrorNotice";
import { ConsentPanel } from "../components/ConsentPanel";
import { SourceForm } from "../components/SourceForm";
import { SourceList } from "../components/SourceList";
import {
  acceptConsent,
  getConsentState,
  getConsentVersion,
  listSources,
  type ConsentState,
} from "../api";

export function SourcesPage() {
  const queryClient = useQueryClient();
  const [sourceOffset, setSourceOffset] = useState(0);
  const consentVersionQuery = useQuery({
    queryKey: queryKeys.consent.version,
    queryFn: getConsentVersion,
  });
  const consentStateQuery = useQuery({
    queryKey: queryKeys.consent.current,
    queryFn: getConsentState,
  });
  const hasConsent = consentStateQuery.data?.accepted === true;
  const sourcesQuery = useQuery({
    queryKey: queryKeys.sources.page(sourceOffset),
    queryFn: () => listSources(sourceOffset),
    enabled: hasConsent,
  });
  const nextSourcesQuery = useQuery({
    queryKey: queryKeys.sources.page(sourceOffset + 100),
    queryFn: () => listSources(sourceOffset + 100),
    enabled: hasConsent && sourcesQuery.data?.items.length === 100,
  });

  useEffect(() => {
    if (sourcesQuery.data?.items.length === 0 && sourceOffset > 0 && hasConsent) {
      setSourceOffset(Math.max(sourceOffset - 100, 0));
    }
  }, [hasConsent, sourceOffset, sourcesQuery.data]);

  const acceptMutation = useMutation({
    mutationFn: acceptConsent,
    onSuccess: async (consent) => {
      queryClient.setQueryData(queryKeys.consent.current, consent);
      await queryClient.invalidateQueries({ queryKey: queryKeys.sources.all });
    },
    onError: (error) => {
      if (error instanceof ApiError && error.status === 409) {
        void queryClient.invalidateQueries({ queryKey: queryKeys.consent.version });
      }
    },
  });

  function refreshConsent() {
    queryClient.setQueryData<ConsentState | undefined>(
      queryKeys.consent.current,
      (current) =>
        current ? { ...current, accepted: false, accepted_at: null } : current,
    );
    void queryClient.invalidateQueries({ queryKey: queryKeys.consent.current });
  }

  if (consentVersionQuery.isPending || consentStateQuery.isPending) {
    return (
      <div className="source-loading" role="status" aria-live="polite">
        <span className="loading-mark" aria-hidden="true">
          ◇
        </span>
        <p>Loading your consent and source status…</p>
      </div>
    );
  }

  if (consentVersionQuery.isError || consentStateQuery.isError) {
    return (
      <section className="source-error-card" aria-labelledby="source-error-title">
        <p className="eyebrow">COULD NOT LOAD YOUR SOURCES</p>
        <h1 id="source-error-title">The service did not respond</h1>
        <p>We could not confirm your current consent. No source was added or fetched.</p>
        <ApiErrorNotice
          error={consentVersionQuery.error ?? consentStateQuery.error}
          fallback="Check your connection and try again."
        />
        <button
          className="quiet-button"
          onClick={() => {
            void consentVersionQuery.refetch();
            void consentStateQuery.refetch();
          }}
          type="button"
        >
          Try again
        </button>
      </section>
    );
  }

  const consent = consentVersionQuery.data;
  const consentState = consentStateQuery.data;
  if (!consent || !consentState) {
    return (
      <section className="source-error-card" role="alert">
        <h1>Consent status is unavailable</h1>
        <p>We cannot safely continue without the current consent version and status.</p>
        <button
          className="quiet-button"
          onClick={() => {
            void consentVersionQuery.refetch();
            void consentStateQuery.refetch();
          }}
          type="button"
        >
          Try again
        </button>
      </section>
    );
  }

  if (!consentState.accepted) {
    return (
      <ConsentPanel
        consent={consent}
        error={acceptMutation.error}
        isPending={acceptMutation.isPending}
        onAccept={() => acceptMutation.mutate(consent.version)}
      />
    );
  }

  return (
    <div className="sources-page">
      <header className="page-heading-row sources-page-heading">
        <div>
          <p className="eyebrow">CONSENT {consentState.version}</p>
          <h1>Your sources, your choice.</h1>
          <p className="page-lede">
            Add only sources you own. A URL will not be fetched unless its ownership is
            verified first.
          </p>
        </div>
      </header>

      <SourceForm
        onConsentRequired={refreshConsent}
        onCreated={() => {
          setSourceOffset(0);
          void queryClient.invalidateQueries({ queryKey: queryKeys.sources.all });
        }}
      />

      {sourcesQuery.isPending ? (
        <div className="source-loading" role="status" aria-live="polite">
          <span className="loading-mark" aria-hidden="true">
            ◇
          </span>
          <p>Loading your sources…</p>
        </div>
      ) : sourcesQuery.isError ? (
        <section className="source-error-card" aria-labelledby="source-list-error-title">
          <h2 id="source-list-error-title">Your source list could not be loaded</h2>
          <ApiErrorNotice
            error={sourcesQuery.error}
            fallback="Check your connection and try again."
          />
          <button
            className="quiet-button"
            onClick={() => void sourcesQuery.refetch()}
            type="button"
          >
            Reload sources
          </button>
        </section>
      ) : (
        <SourceList
          hasNextPage={(nextSourcesQuery.data?.items.length ?? 0) > 0}
          offset={sourceOffset}
          onConsentRequired={refreshConsent}
          onPageChange={setSourceOffset}
          sources={sourcesQuery.data.items}
        />
      )}
    </div>
  );
}
