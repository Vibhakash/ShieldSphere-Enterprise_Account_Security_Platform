import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from "react";
import { api, tokenStore } from "./api";
import type { TokenResponse, UserOut } from "./types";

type AuthState = {
  user: UserOut | null;
  loading: boolean;
  isAuthenticated: boolean;
  refresh: () => Promise<void>;
  login: (email: string, password: string) => Promise<TokenResponse>;
  complete2fa: (code: string, temp_token: string) => Promise<TokenResponse>;
  register: (data: {
    email: string;
    username: string;
    password: string;
    full_name?: string;
  }) => Promise<UserOut>;
  logout: () => Promise<void>;
  setSession: (t: TokenResponse) => Promise<void>;
};

const AuthContext = createContext<AuthState | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<UserOut | null>(null);
  const [loading, setLoading] = useState(true);

  const refresh = useCallback(async () => {
    try {
      const me = await api<UserOut>("/auth/me");
      setUser(me);
    } catch {
      setUser(null);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    refresh();
    const onUnauth = () => setUser(null);
    window.addEventListener("shieldsphere:unauthorized", onUnauth);
    return () => window.removeEventListener("shieldsphere:unauthorized", onUnauth);
  }, [refresh]);

  const setSession = useCallback(
    async (_t: TokenResponse) => {
      tokenStore.clear();
      await refresh();
    },
    [refresh],
  );

  const login = useCallback(
    async (email: string, password: string) => {
      const t = await api<TokenResponse>("/auth/login", {
        auth: false,
        body: {
          email,
          password,
          user_agent: typeof navigator !== "undefined" ? navigator.userAgent : undefined,
        },
      });
      if (!t.requires_2fa) {
        tokenStore.clear();
        await refresh();
      }
      return t;
    },
    [refresh],
  );

  const complete2fa = useCallback(
    async (code: string, temp_token: string) => {
      const t = await api<TokenResponse>("/auth/login/2fa", {
        auth: false,
        body: { code, temp_token },
      });
      tokenStore.clear();
      await refresh();
      return t;
    },
    [refresh],
  );

  const register = useCallback(
    async (data: { email: string; username: string; password: string; full_name?: string }) => {
      return api<UserOut>("/auth/register", { auth: false, body: data });
    },
    [],
  );

  const logout = useCallback(async () => {
    try {
      await api("/auth/logout", { body: {} });
    } catch {
      /* ignore */
    }
    tokenStore.clear();
    setUser(null);
  }, []);

  const value: AuthState = {
    user,
    loading,
    isAuthenticated: !!user,
    refresh,
    login,
    complete2fa,
    register,
    logout,
    setSession,
  };
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within AuthProvider");
  return ctx;
}
