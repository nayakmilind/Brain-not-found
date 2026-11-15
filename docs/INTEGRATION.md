# Frontend/backend integration

## Same-origin routing

In development, Vite proxies `/v1` requests to `http://127.0.0.1:8000`. In
production, serve the SPA and reverse-proxy `/v1` to FastAPI on the same origin.
This avoids cross-origin cookies and means no CORS headers are needed.

If a deployment deliberately uses separate origins, FastAPI must allow only the
exact frontend origin (for example `https://privacy.example.com`), enable
credentials, allow the methods and request headers used by the API
(`Authorization`, `Content-Type`, `Idempotency-Key`, `X-CSRF-Token`,
`X-Request-ID`, and `Last-Event-ID`), and expose `X-Request-ID` and
`Content-Disposition`. Never combine credentialed requests with wildcard
origins. The backend currently has no CORS middleware; configure it only for a
specific deployment origin before using a cross-origin frontend.

## Access and refresh flow

```text
Login/register
  ├─ response body: short-lived access token + user ID
  ├─ HttpOnly, SameSite=Strict refresh cookie
  └─ readable, SameSite=Strict CSRF cookie

SPA memory store
  └─ Authorization: Bearer <access token>

API returns 401
  └─ single-flight POST /v1/auth/refresh
       ├─ browser sends refresh cookie
       ├─ SPA reads CSRF cookie and sends X-CSRF-Token
       ├─ update in-memory access token
       └─ retry the original request once
```

The refresh token is never exposed to JavaScript. The backend scopes it to
`/v1/auth` and the readable CSRF cookie to `/` so the SPA can send the
double-submit header from its root page. Access tokens are not placed in
local/session storage, URLs, logs, or analytics. Logout and unrecoverable
refresh failures clear in-memory auth and TanStack Query state.

## Consent and sources

The authenticated Sources page loads `GET /v1/consent/current-version` and
`GET /v1/consent/current`; source controls remain gated until the user explicitly
accepts that current version using `POST /v1/consent/accept`. The text and
enabled scope shown on the page come from the API.

URL and pasted-text sources use `POST /v1/sources`. File uploads use the raw
request body at `POST /v1/sources/file` with percent-encoded `X-Source-Label`,
`X-Source-Extension`, and `X-Source-Kind` headers; the client does not convert
files to multipart or persist their contents in browser storage. The source list
shows only backend-provided masked label previews.

URL ownership uses the existing challenge and verify endpoints for BIO_TOKEN,
META_TAG, DNS_TXT, or EMAIL_OTP. A challenge token is held only in component
memory and shown with its expiry; the UI does not fetch the URL itself. Email
OTP availability depends on server SMTP configuration. The backend does not
provide an endpoint to recover an active challenge after the page is closed, so
the UI explains that an orphaned challenge must expire before another can be
created.

## Errors and progress

Backend errors currently use FastAPI's JSON error body rather than a complete
RFC 7807 envelope. The API client normalizes both formats into `ApiError`
without discarding the HTTP status or `X-Request-ID`. SSE scan progress uses
the bearer token, pauses while the tab is hidden, refreshes on 401, and provides
a callback for the scan page's polling fallback.
