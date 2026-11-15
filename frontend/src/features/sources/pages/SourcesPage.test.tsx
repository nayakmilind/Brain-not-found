import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { MemoryRouter } from "react-router-dom";
import { useAuthStore } from "../../../auth/store";
import { server } from "../../../test/server";
import { SourcesPage } from "./SourcesPage";

const currentVersion = {
  version: "2026-03",
  scope: {
    assess_only_my_own_sources: true,
    never_request_platform_credentials: true,
    scores_are_estimates_not_safety_guarantees: true,
  },
  statements: [
    "Only submit sources you own.",
    "URLs are not fetched before verification.",
  ],
};

const consentAccepted = {
  accepted: true,
  version: "2026-03",
  scope: currentVersion.scope,
  accepted_at: "2026-03-01T10:00:00Z",
};

function source(overrides: Record<string, unknown> = {}) {
  return {
    id: "c2dfe12a-ff19-4af4-9726-0e366a69d9d4",
    kind: "URL",
    label_preview: "Website URL",
    status: "ACTIVE",
    ownership_status: "UNVERIFIED",
    created_at: "2026-03-01T10:00:00Z",
    ...overrides,
  };
}

function renderSources() {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: { retry: false },
      mutations: { retry: false },
    },
  });
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>
        <SourcesPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

function serveConsent(accepted: boolean) {
  server.use(
    http.get("http://localhost:3000/v1/consent/current-version", () =>
      HttpResponse.json(currentVersion),
    ),
    http.get("http://localhost:3000/v1/consent/current", () =>
      HttpResponse.json(
        accepted
          ? consentAccepted
          : {
              accepted: false,
              version: "2026-03",
              scope: currentVersion.scope,
              accepted_at: null,
            },
      ),
    ),
  );
}

beforeEach(() => {
  useAuthStore.getState().setAuthenticated("test-access-token", "test-user");
});

afterEach(() => {
  cleanup();
  useAuthStore.getState().clear();
  localStorage.clear();
});

describe("consent and source management", () => {
  it("requires explicit acceptance of the current consent version", async () => {
    const user = userEvent.setup();
    serveConsent(false);
    server.use(
      http.post("http://localhost:3000/v1/consent/accept", async ({ request }) => {
        expect(await request.json()).toEqual({
          version: "2026-03",
          accepted: true,
        });
        return HttpResponse.json(consentAccepted);
      }),
      http.get("http://localhost:3000/v1/sources", () =>
        HttpResponse.json({ items: [], limit: 100, offset: 0 }),
      ),
    );
    renderSources();

    expect(await screen.findByText("Only submit sources you own.")).toBeVisible();
    expect(screen.getAllByText("2026-03").length).toBeGreaterThan(0);
    const accept = screen.getByRole("button", { name: /accept and continue/i });
    expect(accept).toBeDisabled();

    await user.click(screen.getByRole("checkbox"));
    expect(accept).toBeEnabled();
    await user.click(accept);

    expect(await screen.findByText("No sources yet")).toBeVisible();
  });

  it("adds pasted text without fetching it and displays only the masked preview", async () => {
    const user = userEvent.setup();
    let listedSources: ReturnType<typeof source>[] = [];
    serveConsent(true);
    server.use(
      http.get("http://localhost:3000/v1/sources", () =>
        HttpResponse.json({ items: listedSources, limit: 100, offset: 0 }),
      ),
      http.post("http://localhost:3000/v1/sources", async ({ request }) => {
        expect(await request.json()).toEqual({
          kind: "TEXT",
          label: "My notes",
          content: "Synthetic text to assess",
        });
        listedSources = [
          source({
            kind: "TEXT",
            label_preview: "Pasted text",
            ownership_status: "SELF_DECLARED",
          }),
        ];
        return HttpResponse.json(listedSources[0], { status: 201 });
      }),
    );
    renderSources();

    await screen.findByText("No sources yet");
    await user.click(screen.getByRole("button", { name: "Pasted text" }));
    await user.type(screen.getByLabelText("Source label"), "My notes");
    await user.type(screen.getByLabelText("Text to assess"), "Synthetic text to assess");
    await user.click(screen.getByRole("button", { name: "Add source" }));

    expect(await screen.findByText(/Source added/)).toBeVisible();
    expect(await screen.findByText("ACTIVE · Self-declared")).toBeVisible();
  });

  it("submits uploaded files as raw bytes with the backend's required headers", async () => {
    const user = userEvent.setup();
    let uploadedSources: ReturnType<typeof source>[] = [];
    serveConsent(true);
    server.use(
      http.get("http://localhost:3000/v1/sources", () =>
        HttpResponse.json({ items: uploadedSources, limit: 100, offset: 0 }),
      ),
      http.post("http://localhost:3000/v1/sources/file", async ({ request }) => {
        expect(request.headers.get("Content-Type")).toBe("text/plain");
        expect(request.headers.get("X-Source-Label")).toBe("My%20export");
        expect(request.headers.get("X-Source-Extension")).toBe("txt");
        expect(request.headers.get("X-Source-Kind")).toBe("PLATFORM_EXPORT");
        expect(await request.text()).toBe("synthetic export");
        const uploaded = source({
          kind: "PLATFORM_EXPORT",
          label_preview: "Uploaded file",
          ownership_status: "SELF_DECLARED",
        });
        uploadedSources = [uploaded];
        return HttpResponse.json(uploaded, { status: 201 });
      }),
    );
    renderSources();

    await screen.findByText("No sources yet");
    await user.click(screen.getByRole("button", { name: "File export" }));
    await user.type(screen.getByLabelText("Source label"), "My export");
    await user.selectOptions(screen.getByLabelText("Upload type"), "PLATFORM_EXPORT");
    const file = new File(["synthetic export"], "export.txt", { type: "text/plain" });
    const fileInput = screen.getByLabelText<HTMLInputElement>("Choose a file");
    await user.upload(fileInput, file);
    expect(fileInput.files).toHaveLength(1);
    await user.click(screen.getByRole("button", { name: "Add source" }));

    expect(await screen.findByText(/Source added/)).toBeVisible();
    expect(await screen.findByText("Uploaded file")).toBeVisible();
  });

  it("displays the ownership token and verifies a URL without sending a proof value", async () => {
    const user = userEvent.setup();
    let verified = false;
    serveConsent(true);
    server.use(
      http.get("http://localhost:3000/v1/sources", () =>
        HttpResponse.json({
          items: [
            source({
              ownership_status: verified ? "VERIFIED" : "UNVERIFIED",
            }),
          ],
          limit: 100,
          offset: 0,
        }),
      ),
      http.post(
        "http://localhost:3000/v1/sources/c2dfe12a-ff19-4af4-9726-0e366a69d9d4/ownership/challenge",
        async ({ request }) => {
          expect(await request.json()).toEqual({ method: "BIO_TOKEN" });
          return HttpResponse.json({
            challenge_id: "5a347b94-c83e-4e16-a47a-91b6616aa799",
            method: "BIO_TOKEN",
            ownership_status: "PENDING",
            token: "shield-verify-synthetic-token",
            instructions: "Add this token to your own profile bio.",
            expires_at: "2026-03-01T10:15:00Z",
          });
        },
      ),
      http.post(
        "http://localhost:3000/v1/sources/c2dfe12a-ff19-4af4-9726-0e366a69d9d4/ownership/verify",
        async ({ request }) => {
          expect(await request.json()).toEqual({
            challenge_id: "5a347b94-c83e-4e16-a47a-91b6616aa799",
            proof: null,
          });
          verified = true;
          return HttpResponse.json({
            verified: true,
            ownership_status: "VERIFIED",
          });
        },
      ),
    );
    renderSources();

    await screen.findByText("Sources you added");
    await user.click(screen.getByRole("button", { name: "Verify ownership" }));
    await user.click(screen.getByRole("button", { name: "Create challenge" }));
    expect(await screen.findByText("shield-verify-synthetic-token")).toBeVisible();
    await user.click(screen.getByRole("button", { name: "Verify ownership" }));

    await waitFor(() => {
      expect(
        screen.getByText("Ownership verified. The source list has been updated."),
      ).toBeVisible();
    });
  });
});
