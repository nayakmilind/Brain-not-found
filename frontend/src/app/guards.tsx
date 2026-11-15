import { Navigate, Outlet } from "react-router-dom";
import { useAuthStore } from "../auth/store";

export function AuthGuard() {
  const status = useAuthStore((state) => state.status);

  if (status === "hydrating") {
    return (
      <main className="startup-screen" aria-live="polite">
        <div className="loading-mark" aria-hidden="true">
          ◇
        </div>
        <p>Restoring your secure session…</p>
      </main>
    );
  }

  if (status !== "authenticated") {
    return <Navigate to="/login" replace />;
  }

  return <Outlet />;
}

export function AnonymousGuard() {
  const status = useAuthStore((state) => state.status);

  if (status === "hydrating") {
    return (
      <main className="startup-screen" aria-live="polite">
        <div className="loading-mark" aria-hidden="true">
          ◇
        </div>
        <p>Restoring your secure session…</p>
      </main>
    );
  }

  if (status === "authenticated") {
    return <Navigate to="/dashboard" replace />;
  }

  return <Outlet />;
}
