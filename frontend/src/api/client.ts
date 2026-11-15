import createClient, { type Middleware } from "openapi-fetch";
import type { components, paths } from "./schema";
import { env } from "../lib/env";
import { useAuthStore } from "../auth/store";
import { toApiError } from "./errors";
import { createRefreshCoordinator } from "./refresh";

export type TokenResponse = components["schemas"]["TokenResponse"];
export type CredentialsRequest = components["schemas"]["CredentialsRequest"];

type SourceFileOperation = paths["/v1/sources/file"]["post"];
type BinarySourcePaths = Omit<paths, "/v1/sources/file"> & {
  "/v1/sources/file": {
    post: Omit<SourceFileOperation, "requestBody"> & {
      requestBody: {
        content: {
          "application/octet-stream": Blob;
          "text/plain": Blob;
          "application/pdf": Blob;
          "application/vnd.openxmlformats-officedocument.wordprocessingml.document": Blob;
        };
      };
    };
  };
};

const apiOrigin =
  env.VITE_API_BASE_URL === "/"
    ? window.location.origin
    : env.VITE_API_BASE_URL.replace(/\/+$/, "");

function readCookie(name: string): string | null {
  const cookie = document.cookie
    .split("; ")
    .find((entry) => entry.startsWith(`${name}=`));
  if (!cookie) {
    return null;
  }
  return decodeURIComponent(cookie.slice(name.length + 1));
}

function requestId(): string {
  return crypto.randomUUID();
}

function authPath(path: string): boolean {
  return path.startsWith("/v1/auth/");
}

function createRequestMiddleware(): Middleware {
  return {
    async onRequest({ request, schemaPath }) {
      const headers = new Headers(request.headers);
      headers.set("X-Request-ID", requestId());

      const accessToken = useAuthStore.getState().accessToken;
      if (accessToken && !authPath(schemaPath)) {
        headers.set("Authorization", `Bearer ${accessToken}`);
      }

      if (schemaPath === "/v1/scans" && request.method === "POST") {
        headers.set("Idempotency-Key", crypto.randomUUID());
      }

      if (schemaPath === "/v1/auth/refresh" || schemaPath === "/v1/auth/logout") {
        const csrfToken = readCookie("psai_csrf");
        if (csrfToken) {
          headers.set("X-CSRF-Token", csrfToken);
        }
      }

      const securedRequest = new Request(request, { headers });
      return securedRequest;
    },
  };
}

async function fetchWithRefresh(request: Request): Promise<Response> {
  const response = await globalThis.fetch(request);
  const path = new URL(request.url).pathname;
  if (response.status !== 401 || authPath(path)) {
    return response;
  }

  let session: TokenResponse | null;
  try {
    session = await refreshSession();
  } catch {
    session = null;
  }
  if (!session) {
    useAuthStore.getState().clear();
    window.dispatchEvent(new Event("psai:auth-expired"));
    return response;
  }

  const headers = new Headers(request.headers);
  headers.set("Authorization", `Bearer ${session.access_token}`);
  const retriedResponse = await globalThis.fetch(new Request(request, { headers }));

  if (retriedResponse.status === 401) {
    useAuthStore.getState().clear();
    window.dispatchEvent(new Event("psai:auth-expired"));
  }
  return retriedResponse;
}

export const api = createClient<paths>({
  baseUrl: apiOrigin,
  credentials: "include",
  fetch: fetchWithRefresh,
});

export const binaryApi = createClient<BinarySourcePaths>({
  baseUrl: apiOrigin,
  credentials: "include",
  fetch: fetchWithRefresh,
});

export const refreshSession = createRefreshCoordinator(async () => {
  const csrfToken = readCookie("psai_csrf");
  if (!csrfToken) {
    return null;
  }

  const result = await api.POST("/v1/auth/refresh");
  if (!("data" in result)) {
    if (result.response.status >= 500) {
      throw toApiError(result.response, result.error);
    }
    return null;
  }

  useAuthStore.getState().setAuthenticated(result.data.access_token, result.data.user_id);
  return result.data;
});

api.use(createRequestMiddleware());
binaryApi.use(createRequestMiddleware());

export async function restoreSession(): Promise<TokenResponse | null> {
  return refreshSession();
}

export async function register(credentials: CredentialsRequest): Promise<TokenResponse> {
  const result = await api.POST("/v1/auth/register", { body: credentials });
  if ("error" in result) {
    throw toApiError(result.response, result.error);
  }
  useAuthStore.getState().setAuthenticated(result.data.access_token, result.data.user_id);
  return result.data;
}

export async function login(credentials: CredentialsRequest): Promise<TokenResponse> {
  const result = await api.POST("/v1/auth/login", { body: credentials });
  if ("error" in result) {
    throw toApiError(result.response, result.error);
  }
  useAuthStore.getState().setAuthenticated(result.data.access_token, result.data.user_id);
  return result.data;
}

export async function logout(): Promise<void> {
  try {
    const result = await api.POST("/v1/auth/logout");
    if ("error" in result) {
      throw toApiError(result.response, result.error);
    }
  } finally {
    useAuthStore.getState().clear();
  }
}
