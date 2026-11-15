import { create } from "zustand";

export type AuthStatus = "hydrating" | "authenticated" | "anonymous";

type AuthState = {
  status: AuthStatus;
  accessToken: string | null;
  userId: string | null;
  notice: string | null;
  setAuthenticated: (accessToken: string, userId: string) => void;
  setStatus: (status: AuthStatus) => void;
  setNotice: (notice: string | null) => void;
  clear: () => void;
};

export const useAuthStore = create<AuthState>((set) => ({
  status: "hydrating",
  accessToken: null,
  userId: null,
  notice: null,
  setAuthenticated: (accessToken, userId) =>
    set({ accessToken, userId, status: "authenticated", notice: null }),
  setStatus: (status) => set({ status }),
  setNotice: (notice) => set({ notice }),
  clear: () =>
    set({
      accessToken: null,
      userId: null,
      status: "anonymous",
      notice: null,
    }),
}));
