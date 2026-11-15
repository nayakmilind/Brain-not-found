export type ApiErrorDetails = {
  status: number;
  code: string;
  title: string;
  detail: string;
  requestId: string | null;
};

function messageFromUnknown(value: unknown): string | null {
  if (typeof value === "string") {
    return value;
  }
  if (Array.isArray(value)) {
    return value
      .map((item) => messageFromUnknown(item))
      .filter((item): item is string => item !== null)
      .join("; ");
  }
  if (typeof value === "object" && value !== null) {
    const record = value as Record<string, unknown>;
    if (typeof record.msg === "string") {
      return record.msg;
    }
    if (typeof record.detail === "string") {
      return record.detail;
    }
  }
  return null;
}

export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly title: string;
  readonly requestId: string | null;

  constructor(details: ApiErrorDetails) {
    super(details.detail);
    this.name = "ApiError";
    this.status = details.status;
    this.code = details.code;
    this.title = details.title;
    this.requestId = details.requestId;
  }
}

export function toApiError(response: Response, payload: unknown): ApiError {
  const record =
    typeof payload === "object" && payload !== null
      ? (payload as Record<string, unknown>)
      : {};
  const detail =
    messageFromUnknown(record.detail) ??
    messageFromUnknown(record.errors) ??
    response.statusText ??
    "The request could not be completed.";
  const title =
    typeof record.title === "string"
      ? record.title
      : response.status === 401
        ? "Sign in required"
        : "Request failed";
  const code =
    typeof record.code === "string"
      ? record.code
      : typeof record.type === "string"
        ? record.type
        : `HTTP_${response.status}`;

  return new ApiError({
    status: response.status,
    code,
    title,
    detail,
    requestId: response.headers.get("X-Request-ID"),
  });
}

export function throwIfApiError<T>(
  result: { data: T; response: Response } | { error: unknown; response: Response },
): T {
  if ("error" in result) {
    throw toApiError(result.response, result.error);
  }
  return result.data;
}
