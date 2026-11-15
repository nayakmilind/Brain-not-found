import { useEffect } from "react";
import { QueryClientProvider } from "@tanstack/react-query";
import { RouterProvider } from "react-router-dom";
import { queryClient } from "./api/queryClient";
import { restoreSession } from "./api/client";
import { useAuthStore } from "./auth/store";
import { ApiError } from "./api/errors";
import { router } from "./app/router";

export function App() {
  const setStatus = useAuthStore((state) => state.setStatus);
  const setNotice = useAuthStore((state) => state.setNotice);

  useEffect(() => {
    let active = true;
    void restoreSession()
      .then((session) => {
        if (active && !session) {
          setStatus("anonymous");
        }
      })
      .catch((error: unknown) => {
        if (!active) {
          return;
        }
        setStatus("anonymous");
        setNotice(
          error instanceof ApiError
            ? `Session restore failed (${error.requestId ?? error.code}).`
            : "The service could not be reached. Sign in again when it is available.",
        );
      });
    return () => {
      active = false;
    };
  }, [setNotice, setStatus]);

  return (
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
    </QueryClientProvider>
  );
}
