import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { afterEach, describe, expect, it } from "vitest";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { useAuthStore } from "../../../auth/store";
import { server } from "../../../test/server";
import { AuthPage } from "./AuthPage";

function renderLogin(path = "/login") {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={[path]}>
        <Routes>
          <Route path="/login" element={<AuthPage mode="login" />} />
          <Route path="/register" element={<AuthPage mode="register" />} />
          <Route path="/dashboard" element={<div>Private workspace</div>} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

afterEach(() => {
  cleanup();
  useAuthStore.getState().clear();
  localStorage.clear();
});

describe("account access", () => {
  it("validates credentials before sending a request", async () => {
    const user = userEvent.setup();
    renderLogin();

    await user.click(screen.getByRole("button", { name: "Sign in" }));

    expect(await screen.findByText("Enter a valid email address.")).toBeVisible();
    expect(await screen.findByText("Use at least 12 characters.")).toBeVisible();
  });

  it("signs in and keeps the access token in memory only", async () => {
    const user = userEvent.setup();
    server.use(
      http.post("http://localhost:3000/v1/auth/login", () =>
        HttpResponse.json({
          user_id: "88c0e337-4653-4f3e-bab0-80a61e42e01a",
          access_token: "in-memory-access-token",
          token_type: "bearer",
          expires_in: 900,
        }),
      ),
    );
    renderLogin();

    await user.type(screen.getByLabelText("Email address"), "avery@example.test");
    await user.type(screen.getByLabelText("Password"), "synthetic-password-123");
    await user.click(screen.getByRole("button", { name: "Sign in" }));

    expect(await screen.findByText("Private workspace")).toBeVisible();
    await waitFor(() => {
      expect(useAuthStore.getState().accessToken).toBe("in-memory-access-token");
    });
    expect(localStorage.length).toBe(0);
  });

  it("shows a request reference with authentication errors", async () => {
    const user = userEvent.setup();
    server.use(
      http.post("http://localhost:3000/v1/auth/login", () =>
        HttpResponse.json(
          { detail: "Invalid email or password" },
          {
            status: 401,
            headers: { "X-Request-ID": "request-example-123" },
          },
        ),
      ),
    );
    renderLogin();

    await user.type(screen.getByLabelText("Email address"), "avery@example.test");
    await user.type(screen.getByLabelText("Password"), "synthetic-password-123");
    await user.click(screen.getByRole("button", { name: "Sign in" }));

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("could not be verified");
    expect(alert).toHaveTextContent("request-example-123");
  });
});
