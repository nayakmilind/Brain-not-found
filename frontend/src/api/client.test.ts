import { beforeEach, describe, expect, it } from "vitest";
import { http, HttpResponse } from "msw";
import { api } from "./client";
import { useAuthStore } from "../auth/store";
import { server } from "../test/server";

const refreshedSession = {
  user_id: "88c0e337-4653-4f3e-bab0-80a61e42e01a",
  access_token: "fresh-access-token",
  token_type: "bearer",
  expires_in: 900,
};

describe("API authentication middleware", () => {
  beforeEach(() => {
    useAuthStore.getState().setAuthenticated("stale-access-token", "user-id");
    document.cookie = "psai_csrf=test-csrf-token; path=/";
  });

  it("uses one cookie refresh for five concurrent unauthorized requests", async () => {
    let refreshCalls = 0;
    let authorizedCalls = 0;

    server.use(
      http.get("http://localhost:3000/v1/consent/current", ({ request }) => {
        const authorization = request.headers.get("Authorization");
        if (authorization !== "Bearer fresh-access-token") {
          return HttpResponse.json({ detail: "Invalid access token" }, { status: 401 });
        }
        authorizedCalls += 1;
        return HttpResponse.json({
          accepted: true,
          version: "2026-03",
          scope: [],
          accepted_at: "2026-01-01T00:00:00Z",
        });
      }),
      http.post("http://localhost:3000/v1/auth/refresh", ({ request }) => {
        refreshCalls += 1;
        expect(request.headers.get("X-CSRF-Token")).toBe("test-csrf-token");
        return HttpResponse.json(refreshedSession);
      }),
    );

    const responses = await Promise.all(
      Array.from({ length: 5 }, () => api.GET("/v1/consent/current")),
    );

    expect(responses.every((response) => response.response.ok)).toBe(true);
    expect(refreshCalls).toBe(1);
    expect(authorizedCalls).toBe(5);
    expect(useAuthStore.getState().accessToken).toBe("fresh-access-token");
    expect(localStorage.length).toBe(0);
  });

  it("does not refresh login failures", async () => {
    let refreshCalls = 0;
    server.use(
      http.post("http://localhost:3000/v1/auth/login", () =>
        HttpResponse.json({ detail: "Invalid email or password" }, { status: 401 }),
      ),
      http.post("http://localhost:3000/v1/auth/refresh", () => {
        refreshCalls += 1;
        return HttpResponse.json(refreshedSession);
      }),
    );

    const result = await api.POST("/v1/auth/login", {
      body: { email: "person@example.test", password: "example-password-123" },
    });

    expect("error" in result).toBe(true);
    expect(refreshCalls).toBe(0);
  });
});
