import { useMutation } from "@tanstack/react-query";
import { Link, useNavigate } from "react-router-dom";
import { queryClient } from "../../../api/queryClient";
import { logout } from "../../../api/client";

export function DashboardPage() {
  const navigate = useNavigate();
  const logoutMutation = useMutation({
    mutationFn: logout,
    onSettled: (_data, error) => {
      queryClient.clear();
      navigate("/login", {
        replace: true,
        state: error
          ? {
              message:
                "You were signed out on this device, but the server could not confirm the logout.",
            }
          : undefined,
      });
    },
  });

  return (
    <div className="dashboard-page">
      <div className="page-heading-row">
        <div>
          <p className="eyebrow">YOUR SPACE</p>
          <h1>Welcome to your privacy workspace.</h1>
          <p className="page-lede">
            Nothing is scanned until you review consent and choose the sources you want to
            assess.
          </p>
        </div>
        <button
          className="quiet-button"
          type="button"
          onClick={() => logoutMutation.mutate()}
          disabled={logoutMutation.isPending}
        >
          {logoutMutation.isPending ? "Signing out…" : "Sign out"}
        </button>
      </div>

      <section className="welcome-panel" aria-labelledby="welcome-title">
        <div className="welcome-art" aria-hidden="true">
          <span className="art-ring art-ring-one" />
          <span className="art-ring art-ring-two" />
          <span className="art-ring art-ring-three" />
          <span className="art-shield">✓</span>
          <span className="art-orbit-dot art-dot-one" />
          <span className="art-orbit-dot art-dot-two" />
        </div>
        <div className="welcome-copy">
          <span className="welcome-label">
            <span className="status-dot" aria-hidden="true" />
            YOUR ACCOUNT IS READY
          </span>
          <h2 id="welcome-title">Start with what you choose to share.</h2>
          <p>
            Add your own source when you’re ready. Website URLs must be ownership-verified
            before scanning; pasted text and uploaded exports stay self-declared and are
            never fetched.
          </p>
          <div className="welcome-next">
            <span className="next-number">01</span>
            <span>
              <strong>Review consent before adding any source.</strong>
              <small>
                You can revoke consent, export, or delete your data at any time.
              </small>
            </span>
          </div>
          <div className="phase-note">
            Consent and source controls are available in Sources. Add a URL only after
            confirming you own it.
          </div>
          <Link className="primary-button dashboard-source-link" to="/sources">
            Review consent and add sources
            <span aria-hidden="true">→</span>
          </Link>
        </div>
      </section>

      <div className="privacy-notes">
        <article className="privacy-note">
          <span className="note-icon note-icon-green" aria-hidden="true">
            ◉
          </span>
          <div>
            <h3>Masked from the start</h3>
            <p>
              Sensitive values are masked by default. Reveals are explicit and audited.
            </p>
          </div>
        </article>
        <article className="privacy-note">
          <span className="note-icon note-icon-blue" aria-hidden="true">
            ⌁
          </span>
          <div>
            <h3>Estimates, with context</h3>
            <p>
              Any future score will show its factors and limitations—not a safety
              guarantee.
            </p>
          </div>
        </article>
        <article className="privacy-note">
          <span className="note-icon note-icon-gold" aria-hidden="true">
            ↗
          </span>
          <div>
            <h3>You stay in control</h3>
            <p>
              Only your selected sources can be assessed, and you can remove them anytime.
            </p>
          </div>
        </article>
      </div>
    </div>
  );
}
