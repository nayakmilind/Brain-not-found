import { zodResolver } from "@hookform/resolvers/zod";
import { useMutation } from "@tanstack/react-query";
import { useState } from "react";
import { useForm, useWatch } from "react-hook-form";
import { Link, useLocation, useNavigate } from "react-router-dom";
import { ApiError } from "../../../api/errors";
import { login, register } from "../../../api/client";
import { Brand } from "../../../components/Brand";
import { credentialsSchema, type CredentialsForm } from "../schemas";
import { useAuthStore } from "../../../auth/store";

type AuthPageProps = {
  mode: "login" | "register";
};

function passwordStrength(password: string): number {
  if (!password) {
    return 0;
  }
  return [
    password.length >= 12,
    /[a-z]/.test(password) && /[A-Z]/.test(password),
    /\d/.test(password),
    /[^a-zA-Z0-9]/.test(password),
  ].filter(Boolean).length;
}

function errorCopy(error: unknown): {
  message: string;
  requestId: string | null;
} {
  if (error instanceof ApiError) {
    if (error.status === 401) {
      return {
        message: "Those sign-in details could not be verified. Check them and try again.",
        requestId: error.requestId,
      };
    }
    if (error.status === 409) {
      return {
        message: "An account with this email already exists. Try signing in instead.",
        requestId: error.requestId,
      };
    }
    if (error.status === 429) {
      return {
        message: "Too many attempts. Wait a little before trying again.",
        requestId: error.requestId,
      };
    }
    return { message: error.message, requestId: error.requestId };
  }
  return {
    message: "We could not reach Privacy Shield. Check your connection and try again.",
    requestId: null,
  };
}

export function AuthPage({ mode }: AuthPageProps) {
  const isRegister = mode === "register";
  const navigate = useNavigate();
  const location = useLocation();
  const startupNotice = useAuthStore((state) => state.notice);
  const [passwordVisible, setPasswordVisible] = useState(false);
  const {
    register: registerField,
    handleSubmit,
    control,
    formState: { errors },
  } = useForm<CredentialsForm>({
    resolver: zodResolver(credentialsSchema),
    mode: "onBlur",
    defaultValues: { email: "", password: "" },
  });
  const password = useWatch({ control, name: "password" });
  const mutation = useMutation({
    mutationFn: (credentials: CredentialsForm) =>
      isRegister ? register(credentials) : login(credentials),
    onSuccess: () => navigate("/dashboard", { replace: true }),
  });
  const strength = passwordStrength(password ?? "");
  const mutationError = mutation.error ? errorCopy(mutation.error) : null;
  const routeNotice =
    typeof location.state === "object" &&
    location.state !== null &&
    "message" in location.state &&
    typeof location.state.message === "string"
      ? location.state.message
      : null;
  const notice = startupNotice ?? routeNotice;

  const onSubmit = handleSubmit((credentials) => {
    mutation.mutate(credentials);
  });

  return (
    <main className="auth-page">
      <div className="auth-topbar">
        <Brand />
        <span className="auth-topbar-note">
          <span className="status-dot" aria-hidden="true" />
          Your data stays yours
        </span>
      </div>

      <div className="auth-layout">
        <section className="auth-story" aria-labelledby="story-title">
          <div className="story-kicker">
            <span className="kicker-line" />A clearer view of your digital footprint
          </div>
          <h1 id="story-title">
            Know what’s
            <br />
            <span>out there.</span>
            <br />
            Choose what’s next.
          </h1>
          <p className="story-description">
            Understand how your public details connect—and make thoughtful changes, at
            your own pace.
          </p>
          <div className="story-assurances">
            <div className="assurance">
              <span className="assurance-icon" aria-hidden="true">
                ✓
              </span>
              <span>
                <strong>Your sources, your choice</strong>
                <small>Only sources you add can be assessed.</small>
              </span>
            </div>
            <div className="assurance">
              <span className="assurance-icon" aria-hidden="true">
                ◌
              </span>
              <span>
                <strong>Private by default</strong>
                <small>Sensitive details stay masked until you reveal them.</small>
              </span>
            </div>
            <div className="assurance">
              <span className="assurance-icon" aria-hidden="true">
                ↗
              </span>
              <span>
                <strong>Clear, not alarmist</strong>
                <small>Every estimate comes with an explanation.</small>
              </span>
            </div>
          </div>
          <div className="story-orbit story-orbit-one" aria-hidden="true" />
          <div className="story-orbit story-orbit-two" aria-hidden="true" />
          <div className="story-orbit story-orbit-three" aria-hidden="true" />
          <div className="story-spark story-spark-one" aria-hidden="true">
            ✳
          </div>
          <div className="story-spark story-spark-two" aria-hidden="true">
            ·
          </div>
        </section>

        <section className="auth-card" aria-labelledby="form-title">
          <div className="card-heading">
            <p className="eyebrow">
              {isRegister ? "START WITH CONTROL" : "WELCOME BACK"}
            </p>
            <h2 id="form-title">
              {isRegister ? "Create your account" : "Sign in to your account"}
            </h2>
            <p>
              {isRegister
                ? "Your privacy workspace is personal to you."
                : "Pick up where you left off, securely."}
            </p>
          </div>

          {notice && (
            <div className="notice-banner" role="status">
              {notice}
            </div>
          )}
          {mutationError && (
            <div className="error-banner" role="alert">
              <span className="error-icon" aria-hidden="true">
                !
              </span>
              <span>
                {mutationError.message}
                {mutationError.requestId && (
                  <small>Support reference: {mutationError.requestId}</small>
                )}
              </span>
            </div>
          )}

          <form className="auth-form" onSubmit={onSubmit} noValidate>
            <div className="form-field">
              <label htmlFor="email">Email address</label>
              <input
                id="email"
                type="email"
                autoComplete="email"
                inputMode="email"
                placeholder="you@example.com"
                aria-invalid={Boolean(errors.email)}
                aria-describedby={errors.email ? "email-error" : undefined}
                {...registerField("email")}
              />
              {errors.email && (
                <span className="field-error" id="email-error">
                  {errors.email.message}
                </span>
              )}
            </div>

            <div className="form-field">
              <div className="label-row">
                <label htmlFor="password">Password</label>
                {!isRegister && (
                  <span className="field-hint">At least 12 characters</span>
                )}
              </div>
              <div className="password-control">
                <input
                  id="password"
                  type={passwordVisible ? "text" : "password"}
                  autoComplete={isRegister ? "new-password" : "current-password"}
                  placeholder={
                    isRegister ? "Create a strong password" : "Enter your password"
                  }
                  aria-invalid={Boolean(errors.password)}
                  aria-describedby={
                    errors.password
                      ? "password-error"
                      : isRegister
                        ? "password-strength"
                        : undefined
                  }
                  {...registerField("password")}
                />
                <button
                  className="password-toggle"
                  type="button"
                  aria-label={passwordVisible ? "Hide password" : "Show password"}
                  aria-pressed={passwordVisible}
                  onClick={() => setPasswordVisible((visible) => !visible)}
                >
                  {passwordVisible ? "Hide" : "Show"}
                </button>
              </div>
              {errors.password && (
                <span className="field-error" id="password-error">
                  {errors.password.message}
                </span>
              )}
              {isRegister && (
                <div className="strength-meter" id="password-strength">
                  <div
                    className="strength-track"
                    role="progressbar"
                    aria-label="Password strength"
                    aria-valuemin={0}
                    aria-valuemax={4}
                    aria-valuenow={strength}
                  >
                    {Array.from({ length: 4 }, (_, index) => (
                      <span
                        key={index}
                        className={
                          index < strength
                            ? "strength-segment filled"
                            : "strength-segment"
                        }
                      />
                    ))}
                  </div>
                  <span>
                    {strength < 2
                      ? "Use a longer, varied password"
                      : strength < 4
                        ? "Good start"
                        : "Strong"}
                  </span>
                </div>
              )}
            </div>

            <button
              className="primary-button"
              type="submit"
              disabled={mutation.isPending}
              aria-busy={mutation.isPending}
            >
              {mutation.isPending
                ? "Please wait…"
                : isRegister
                  ? "Create account"
                  : "Sign in"}
              {!mutation.isPending && <span aria-hidden="true">→</span>}
            </button>
          </form>

          <div className="form-divider">
            <span />
            <span>SECURE BY DESIGN</span>
            <span />
          </div>
          <p className="credential-note">
            This password is only for your Privacy Shield account. We never ask for
            social-media passwords or credentials.
          </p>
          <p className="auth-switch">
            {isRegister ? "Already have an account?" : "New to Privacy Shield?"}{" "}
            <Link to={isRegister ? "/login" : "/register"}>
              {isRegister ? "Sign in" : "Create an account"}
            </Link>
          </p>
        </section>
      </div>

      <footer className="auth-footer">
        <span>Privacy Shield AI</span>
        <span>Consent first · Masked by default · Always yours</span>
      </footer>
    </main>
  );
}
