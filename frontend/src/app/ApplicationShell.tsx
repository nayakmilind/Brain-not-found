import { useEffect } from "react";
import { NavLink, Outlet, useNavigate } from "react-router-dom";
import { queryClient } from "../api/queryClient";
import { useAuthStore } from "../auth/store";
import { Brand } from "../components/Brand";

export function ApplicationShell() {
  const navigate = useNavigate();

  useEffect(() => {
    const expireSession = () => {
      queryClient.clear();
      navigate("/login", { replace: true });
    };
    window.addEventListener("psai:auth-expired", expireSession);
    return () => window.removeEventListener("psai:auth-expired", expireSession);
  }, [navigate]);

  const userId = useAuthStore((state) => state.userId);

  return (
    <div className="app-shell">
      <header className="app-header">
        <Brand href="/dashboard" />
        <div className="session-indicator">
          <span className="status-dot" aria-hidden="true" />
          <span>Private session</span>
        </div>
      </header>
      <main className="workspace-main">
        <nav className="workspace-rail" aria-label="Main navigation">
          <span className="rail-label">WORKSPACE</span>
          <NavLink
            className={({ isActive }) =>
              isActive ? "rail-link rail-link-active" : "rail-link"
            }
            to="/dashboard"
          >
            <span aria-hidden="true">◫</span>
            Overview
          </NavLink>
          <NavLink
            className={({ isActive }) =>
              isActive ? "rail-link rail-link-active" : "rail-link"
            }
            to="/sources"
          >
            <span aria-hidden="true">▤</span>
            Sources
          </NavLink>
          <div className="rail-note">
            <span className="rail-note-icon" aria-hidden="true">
              ◈
            </span>
            <p>Your sources and findings stay private to your account.</p>
          </div>
          <div className="rail-account">
            <span className="account-avatar" aria-hidden="true">
              {userId?.slice(0, 1).toUpperCase() ?? "P"}
            </span>
            <span>
              <strong>Personal account</strong>
              <small>Signed in securely</small>
            </span>
          </div>
        </nav>
        <section className="workspace-content">
          <Outlet />
        </section>
      </main>
      <footer className="app-footer">
        <span>Built for your privacy, not against it.</span>
        <span>Nothing is scanned without your consent.</span>
      </footer>
    </div>
  );
}
