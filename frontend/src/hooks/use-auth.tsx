"use client";

import { useRouter } from "next/navigation";
import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";

import { UNAUTHORIZED_EVENT } from "@/lib/api-client";
import { ApiError } from "@/lib/errors";
import { authService } from "@/services/auth.service";
import type { LoginPayload, RegisterPayload, User } from "@/types/user";

type AuthStatus = "loading" | "authenticated" | "unauthenticated";

interface AuthContextValue {
  user: User | null;
  status: AuthStatus;
  login: (payload: LoginPayload) => Promise<User>;
  register: (payload: RegisterPayload) => Promise<User>;
  logout: () => Promise<void>;
  setUser: (user: User) => void;
  refresh: () => Promise<void>;
}

const AuthContext = createContext<AuthContextValue | null>(null);

/**
 * Holds the signed-in user for the whole app.
 *
 * The session itself lives in an httpOnly cookie the browser manages, so this
 * provider never sees a token — it asks the API who the caller is and caches
 * the answer.
 */
export function AuthProvider({ children }: { children: ReactNode }) {
  const router = useRouter();
  const [user, setUserState] = useState<User | null>(null);
  const [status, setStatus] = useState<AuthStatus>("loading");

  const [sessionToken, setSessionToken] = useState(0);

  // Resolve the cookie into a user on mount, and whenever `refresh` is called.
  // State is only touched from the promise callbacks, never synchronously in
  // the effect body, so a re-render cascade cannot occur.
  useEffect(() => {
    let active = true;

    authService
      .me()
      .then((currentUser) => {
        if (!active) return;
        setUserState(currentUser);
        setStatus("authenticated");
      })
      .catch((error: unknown) => {
        if (!active) return;
        // A 401 here simply means "not signed in"; anything else is still a
        // reason to treat the app as signed out, since nothing can be fetched.
        if (!(error instanceof ApiError) || !error.isUnauthorized) {
          console.error("Failed to resolve the current session", error);
        }
        setUserState(null);
        setStatus("unauthenticated");
      });

    return () => {
      active = false;
    };
  }, [sessionToken]);

  const refresh = useCallback(async () => {
    setSessionToken((token) => token + 1);
  }, []);

  // The API rejected a request as unauthenticated: drop local state so the
  // guarded screens stop rendering data for a session that no longer exists.
  useEffect(() => {
    const handleUnauthorized = () => {
      setUserState(null);
      setStatus("unauthenticated");
      router.replace("/login?reason=expired");
    };
    window.addEventListener(UNAUTHORIZED_EVENT, handleUnauthorized);
    return () => window.removeEventListener(UNAUTHORIZED_EVENT, handleUnauthorized);
  }, [router]);

  const login = useCallback(async (payload: LoginPayload) => {
    const { user: signedIn } = await authService.login(payload);
    setUserState(signedIn);
    setStatus("authenticated");
    return signedIn;
  }, []);

  const register = useCallback(async (payload: RegisterPayload) => {
    const { user: created } = await authService.register(payload);
    setUserState(created);
    setStatus("authenticated");
    return created;
  }, []);

  const logout = useCallback(async () => {
    try {
      await authService.logout();
    } finally {
      // Clear locally even if the request failed, so the UI never claims to be
      // signed in when the user asked to leave.
      setUserState(null);
      setStatus("unauthenticated");
      router.replace("/login");
    }
  }, [router]);

  const value = useMemo<AuthContextValue>(
    () => ({ user, status, login, register, logout, setUser: setUserState, refresh }),
    [user, status, login, register, logout, refresh],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextValue {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error("useAuth must be used inside an <AuthProvider>.");
  }
  return context;
}
