import { fetchEventSource, type EventSourceMessage } from "@microsoft/fetch-event-source";
import { useAuthStore } from "../auth/store";
import { env } from "../lib/env";
import { refreshSession } from "./client";

type ScanStatus =
  | "QUEUED"
  | "FETCHING"
  | "ANALYZING"
  | "SCORING"
  | "RECOMMENDING"
  | "DONE"
  | "FAILED"
  | "CANCELLED";

export type ScanProgressEvent = {
  scan_id: string;
  status: ScanStatus;
  stage_checkpoint: string;
  message: string;
  created_at: string;
};

const terminalStatuses = new Set<ScanStatus>(["DONE", "FAILED", "CANCELLED"]);
class RetryAfterRefresh extends Error {}
const refreshAccessToken = async () => {
  const session = await refreshSession();
  return session?.access_token ?? null;
};

function parseProgressEvent(value: string): ScanProgressEvent | null {
  try {
    const event: unknown = JSON.parse(value);
    if (typeof event !== "object" || event === null) {
      return null;
    }
    const statuses: ScanStatus[] = [
      "QUEUED",
      "FETCHING",
      "ANALYZING",
      "SCORING",
      "RECOMMENDING",
      "DONE",
      "FAILED",
      "CANCELLED",
    ];
    const record = event as Record<string, unknown>;
    const status =
      typeof record.status === "string"
        ? statuses.find((candidate) => candidate === record.status)
        : undefined;
    if (
      typeof record.scan_id !== "string" ||
      status === undefined ||
      typeof record.stage_checkpoint !== "string" ||
      typeof record.message !== "string" ||
      typeof record.created_at !== "string"
    ) {
      return null;
    }
    return {
      scan_id: record.scan_id,
      status,
      stage_checkpoint: record.stage_checkpoint,
      message: record.message,
      created_at: record.created_at,
    };
  } catch {
    return null;
  }
}

export async function streamScanEvents(
  scanId: string,
  signal: AbortSignal,
  onProgress: (event: ScanProgressEvent) => void,
  onFallbackToPolling: () => void,
): Promise<void> {
  const baseUrl =
    env.VITE_API_BASE_URL === "/"
      ? window.location.origin
      : env.VITE_API_BASE_URL.replace(/\/+$/, "");
  const accessToken = useAuthStore.getState().accessToken;
  const headers: Record<string, string> = {
    "X-Request-ID": crypto.randomUUID(),
  };
  if (accessToken) {
    headers.Authorization = `Bearer ${accessToken}`;
  }
  const streamController = new AbortController();
  const abortStream = () => streamController.abort();
  if (signal.aborted) {
    streamController.abort();
  }
  signal.addEventListener("abort", abortStream, { once: true });
  let shouldFallback = false;
  let terminalEvent = false;

  try {
    await fetchEventSource(`${baseUrl}/v1/scans/${encodeURIComponent(scanId)}/events`, {
      credentials: "include",
      headers,
      signal: streamController.signal,
      openWhenHidden: false,
      async onopen(response) {
        if (response.status === 401) {
          const refreshed = await refreshAccessToken();
          if (!refreshed) {
            useAuthStore.getState().clear();
            throw new Error("Authentication expired");
          }
          headers.Authorization = `Bearer ${refreshed}`;
          throw new RetryAfterRefresh();
        }
        if (!response.ok) {
          throw new Error(`Scan event stream returned ${response.status}`);
        }
      },
      onmessage(message: EventSourceMessage) {
        if (message.event !== "progress") {
          return;
        }
        const progress = parseProgressEvent(message.data);
        if (!progress) {
          throw new Error("Scan event stream returned an invalid progress event");
        }
        onProgress(progress);
        if (terminalStatuses.has(progress.status)) {
          terminalEvent = true;
          streamController.abort();
        }
      },
      onclose() {
        shouldFallback = !terminalEvent;
      },
      onerror(error) {
        if (error instanceof RetryAfterRefresh) {
          return 100;
        }
        shouldFallback = true;
        throw error;
      },
    });
  } catch {
    shouldFallback = !signal.aborted && !terminalEvent;
  } finally {
    signal.removeEventListener("abort", abortStream);
  }

  if (shouldFallback && !signal.aborted && !terminalEvent) {
    onFallbackToPolling();
  }
}
