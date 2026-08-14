import { API_BASE } from "./api";

/**
 * Auth transport.
 *
 * `credentials: "include"` on every call is what makes the session work: the
 * token lives in an HttpOnly cookie that JavaScript deliberately cannot read,
 * so it can only travel by being attached automatically to the request. There
 * is no token in localStorage on purpose - anything JS can read, an XSS bug can
 * steal.
 */

export interface AuthUser {
  id: number;
  email: string;
}

export class AuthRequestError extends Error {
  readonly status: number;
  constructor(message: string, status: number) {
    super(message);
    this.name = "AuthRequestError";
    this.status = status;
  }
}

async function post(path: string, body?: unknown): Promise<Response> {
  return fetch(`${API_BASE}${path}`, {
    method: "POST",
    credentials: "include",
    headers: { "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}

async function readError(res: Response, fallback: string): Promise<string> {
  try {
    const data = await res.json();
    if (typeof data?.detail === "string") return data.detail;
    // FastAPI validation errors arrive as a list of objects; surface the first
    // readable message rather than rendering "[object Object]".
    if (Array.isArray(data?.detail) && typeof data.detail[0]?.msg === "string") {
      return data.detail[0].msg;
    }
  } catch {
    /* non-JSON body */
  }
  return fallback;
}

export async function signup(email: string, password: string): Promise<AuthUser> {
  const res = await post("/auth/signup", { email, password });
  if (!res.ok) {
    throw new AuthRequestError(
      await readError(res, "Could not create the account."),
      res.status
    );
  }
  return (await res.json()) as AuthUser;
}

export async function login(email: string, password: string): Promise<AuthUser> {
  const res = await post("/auth/login", { email, password });
  if (!res.ok) {
    throw new AuthRequestError(
      await readError(res, "Incorrect email or password."),
      res.status
    );
  }
  return (await res.json()) as AuthUser;
}

export async function logout(): Promise<void> {
  // Failure is deliberately ignored: the cookie is cleared server-side, and a
  // network blip must never leave someone stuck in a "logged in" UI.
  try {
    await post("/auth/logout");
  } catch {
    /* no-op */
  }
}

/** Returns the signed-in user, or null. Never throws for "not signed in". */
export async function fetchCurrentUser(signal?: AbortSignal): Promise<AuthUser | null> {
  try {
    const res = await fetch(`${API_BASE}/auth/me`, {
      credentials: "include",
      signal,
    });
    if (res.status === 401) return null;
    if (!res.ok) return null;
    return (await res.json()) as AuthUser;
  } catch {
    // Backend unreachable is treated as "not authenticated" so the guard fails
    // closed rather than letting someone through on a network error.
    return null;
  }
}
