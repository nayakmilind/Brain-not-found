import { QueryClient } from "@tanstack/react-query";
import { ApiError } from "./errors";

function shouldRetry(failureCount: number, error: unknown): boolean {
  if (error instanceof ApiError) {
    return error.status >= 500 && failureCount < 2;
  }
  return error instanceof TypeError && failureCount < 2;
}

export const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 30_000,
      retry: shouldRetry,
      refetchOnWindowFocus: false,
    },
    mutations: {
      retry: false,
    },
  },
});
