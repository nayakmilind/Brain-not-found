# Privacy Shield AI

**Repository:** Brain-not-found

Privacy Shield AI is a consent-first platform for helping people assess and reduce their own public digital footprint.

It does not collect social-media credentials or bypass platform protections.

## Frontend (F1–F2)

The React/Vite frontend is in `frontend/`. Follow [frontend/README.md](./frontend/README.md) for setup and quality commands.

The app includes account screens, versioned consent, source management, and URL ownership verification.

For local development, start the API stack first. Vite proxies `/v1` to `http://127.0.0.1:8000`.

See [docs/INTEGRATION.md](./docs/INTEGRATION.md) for authentication, CSRF, and deployment guidance.

Scan, findings, and report screens are not yet available.

## M0 Local Setup

Requirements: Docker Compose and `uv` with Python 3.12 available.

1. Copy `.env.example` to `.env`.
2. Generate three independent 32-byte secrets:

```powershell
uv run python -c "import base64, secrets; print(base64.b64encode(secrets.token_bytes(32)).decode())"