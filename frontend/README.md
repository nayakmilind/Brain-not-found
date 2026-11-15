# Privacy Shield AI frontend

The frontend is a React 18, Vite, and strict TypeScript application. It connects
to the FastAPI contract through `openapi-fetch`; generated API types are checked
in at `src/api/schema.d.ts`.

## Local development

Requirements: Node.js 22+ and Corepack/pnpm.

1. Start the backend and its PostgreSQL/Redis dependencies. The backend must be
   available at `http://127.0.0.1:8000`.
2. Install dependencies and generate types from the running backend:

   ```powershell
   corepack pnpm install
   corepack pnpm gen:api
   ```

3. Copy `.env.example` to `.env.local` if you need to change the defaults.
4. Start Vite:

   ```powershell
   corepack pnpm dev
   ```

Vite proxies `/v1` to the backend so browser requests are same-origin during
development. The frontend does not persist access tokens. The refresh token is
an HttpOnly cookie; only the CSRF cookie is readable by the client so it can
send the required `X-CSRF-Token` header.

## Quality commands

```powershell
corepack pnpm lint
corepack pnpm typecheck
corepack pnpm test
corepack pnpm build
```

Run `pnpm gen:api` after backend contract changes. Do not edit the generated
schema file by hand.

## Current phase

F1 account access and the F2 consent/source flows are implemented. URL sources
remain unscannable until the backend confirms ownership; pasted text and file
uploads are marked self-declared and are never fetched. Scans, findings,
monitoring, reports, and privacy-centre screens remain later frontend phases.
