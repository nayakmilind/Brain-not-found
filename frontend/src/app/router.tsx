import { createBrowserRouter, Navigate } from "react-router-dom";
import { ApplicationShell } from "./ApplicationShell";
import { AuthPage } from "../features/auth/pages/AuthPage";
import { DashboardPage } from "../features/auth/pages/DashboardPage";
import { SourcesPage } from "../features/sources/pages/SourcesPage";
import { AuthGuard, AnonymousGuard } from "./guards";

export const router = createBrowserRouter([
  {
    element: <AnonymousGuard />,
    children: [
      { path: "/login", element: <AuthPage mode="login" /> },
      { path: "/register", element: <AuthPage mode="register" /> },
    ],
  },
  {
    element: <AuthGuard />,
    children: [
      {
        element: <ApplicationShell />,
        children: [
          { path: "/dashboard", element: <DashboardPage /> },
          { path: "/sources", element: <SourcesPage /> },
        ],
      },
    ],
  },
  { path: "*", element: <Navigate to="/login" replace /> },
]);
