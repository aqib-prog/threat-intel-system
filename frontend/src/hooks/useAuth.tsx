import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import { fetchCurrentUser, login as apiLogin, logout as apiLogout, signup as apiSignup, type AuthUser } from "../lib/authApi";

/**
 * Session state for the whole app.
 *
 * The source of truth is the server, not this context: on mount it asks
 * /auth/me, and every protected API call is independently enforced by the
 * backend. This exists so the UI can show the right screen, not so it can
 * decide who is allowed in.
 */

interface AuthContextValue {
  user: AuthUser | null;
  /** True until the initial session check resolves. Guards must WAIT on this. */
  loading: boolean;
  signIn: (email: string, password: string) => Promise<void>;
  register: (email: string, password: string) => Promise<void>;
  signOut: () => Promise<void>;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<AuthUser | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const controller = new AbortController();
    fetchCurrentUser(controller.signal)
      .then(setUser)
      .finally(() => setLoading(false));
    return () => controller.abort();
  }, []);

  const signIn = useCallback(async (email: string, password: string) => {
    setUser(await apiLogin(email, password));
  }, []);

  const register = useCallback(async (email: string, password: string) => {
    setUser(await apiSignup(email, password));
  }, []);

  const signOut = useCallback(async () => {
    await apiLogout();
    setUser(null);
  }, []);

  const value = useMemo(
    () => ({ user, loading, signIn, register, signOut }),
    [user, loading, signIn, register, signOut]
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextValue {
  const context = useContext(AuthContext);
  if (!context) throw new Error("useAuth must be used inside <AuthProvider>");
  return context;
}
