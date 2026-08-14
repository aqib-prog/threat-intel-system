import { useMemo, useRef, useState, type FormEvent } from "react";
import { Link, Navigate, useLocation, useNavigate } from "react-router-dom";
import { AnimatePresence, motion } from "framer-motion";
import { ArrowRight, Eye, EyeSlash, WarningCircle } from "@phosphor-icons/react";
import { AuthBackdrop } from "../components/auth/AuthBackdrop";
import { ClearanceRings, type RingState } from "../components/auth/ClearanceRings";
import { Logo } from "../components/shared/Logo";
import { useAuth } from "../hooks/useAuth";
import { AuthRequestError } from "../lib/authApi";

/**
 * Login and sign-up.
 *
 * One component for both modes: the fields, validation, and clearance visual
 * are identical, and only the copy, the endpoint, and the strictness of the
 * password rule differ. Splitting them into two files would have duplicated the
 * security-sensitive parts, which is exactly where drift causes bugs.
 */

// Mirrors the backend's own rule (auth/settings.py AUTH_MIN_PASSWORD_LENGTH).
// The server is still the authority - this only tells the user sooner.
const MIN_PASSWORD_LENGTH = 12;
const EMAIL_SHAPE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;

const ACCENT = {
  cyan: "#00f5ff",
  green: "#00ff88",
  purple: "#7c3aed",
};

export function AuthPage({ mode }: { mode: "login" | "signup" }) {
  const isSignup = mode === "signup";
  const { user, loading, signIn, register } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const formRef = useRef<HTMLFormElement>(null);

  // Where the guard wanted to send them before the redirect. Falls back to the
  // console rather than the landing page - someone who just signed in is trying
  // to get to work.
  const destination =
    (location.state as { from?: { pathname?: string } } | null)?.from?.pathname || "/chat";

  const emailValid = EMAIL_SHAPE.test(email.trim());
  const passwordStrength = Math.min(1, password.length / MIN_PASSWORD_LENGTH);
  const passwordValid = isSignup
    ? password.length >= MIN_PASSWORD_LENGTH
    : password.length > 0;

  const rings: RingState[] = useMemo(
    () => [
      {
        label: "Identity — a valid address",
        progress: emailValid ? 1 : Math.min(0.85, email.length / 14),
        satisfied: emailValid,
        hex: ACCENT.cyan,
      },
      {
        label: isSignup
          ? `Secret — ${MIN_PASSWORD_LENGTH}+ characters`
          : "Secret — entered",
        progress: isSignup ? passwordStrength : password.length > 0 ? 1 : 0,
        satisfied: passwordValid,
        hex: ACCENT.green,
      },
      {
        label: "Channel — encrypted session",
        progress: emailValid && passwordValid ? 1 : 0.12,
        satisfied: emailValid && passwordValid,
        hex: ACCENT.purple,
      },
    ],
    [email, emailValid, isSignup, password.length, passwordStrength, passwordValid]
  );

  const ready = emailValid && passwordValid && !submitting;

  // Report only the FIRST unmet requirement, in field order. Listing everything
  // at once reads as a wall of failure; naming the next step reads as progress.
  const blockedReason =
    submitting || ready
      ? null
      : !email
        ? "Enter your email to continue"
        : !emailValid
          ? "That email is not a valid address yet"
          : !password
            ? "Enter your password to continue"
            : isSignup
              ? `Password needs ${MIN_PASSWORD_LENGTH - password.length} more character${
                  MIN_PASSWORD_LENGTH - password.length === 1 ? "" : "s"
                }`
              : null;

  // Already signed in: never show a login form to someone who has a session.
  if (!loading && user) return <Navigate to={destination} replace />;

  const handleSubmit = async (event: FormEvent) => {
    event.preventDefault();
    if (!ready) return;
    setSubmitting(true);
    setError(null);
    try {
      if (isSignup) await register(email.trim(), password);
      else await signIn(email.trim(), password);
      navigate(destination, { replace: true });
    } catch (err) {
      const message =
        err instanceof AuthRequestError
          ? err.message
          : "Could not reach the server. Check your connection and try again.";
      setError(message);
      // A failed attempt shakes the panel: the feedback is physical and
      // immediate, so it registers before the message is even read.
      formRef.current?.animate(
        [
          { transform: "translateX(0)" },
          { transform: "translateX(-7px)" },
          { transform: "translateX(6px)" },
          { transform: "translateX(-3px)" },
          { transform: "translateX(0)" },
        ],
        { duration: 320, easing: "ease-out" }
      );
    } finally {
      setSubmitting(false);
    }
  };

  const fieldClass =
    "peer w-full rounded-lg border bg-transparent px-3 py-2.5 font-mono text-sm text-white outline-none transition-colors placeholder:text-text-dim";

  return (
    <div className="relative flex min-h-dvh items-center justify-center px-5 py-10">
      <AuthBackdrop />

      <motion.div
        initial={{ opacity: 0, y: 18 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5, ease: [0.16, 1, 0.3, 1] }}
        className="relative z-10 w-full max-w-4xl overflow-hidden rounded-2xl border border-cyan/20"
        style={{
          background:
            "linear-gradient(150deg, rgba(0,245,255,0.07) 0%, rgba(10,10,18,0.94) 42%, rgba(124,58,237,0.07) 100%), rgba(8,8,14,0.96)",
          boxShadow:
            "inset 0 1px 0 rgba(255,255,255,0.13), 0 44px 100px -46px rgba(0,245,255,0.45)",
        }}
      >
        <div className="grid lg:grid-cols-[1fr_1.05fr]">
          {/* Clearance panel */}
          <div className="hidden flex-col items-center justify-center gap-2 border-r border-border-dim px-8 py-12 lg:flex">
            <ClearanceRings rings={rings} unlocked={emailValid && passwordValid} />
          </div>

          {/* Form */}
          <div className="px-7 py-9 sm:px-10 sm:py-11">
            {/* Logo already renders the wordmark - adding another printed it twice. */}
            <Link to="/" className="inline-flex no-underline">
              <Logo size={26} />
            </Link>

            <h1 className="mt-7 font-display text-2xl font-semibold tracking-tight text-white">
              {isSignup ? "Request access" : "Authenticate"}
            </h1>
            <p className="mt-1.5 text-sm text-text-mid">
              {isSignup
                ? "Create the credentials that will unlock the console."
                : "Present your credentials to open the console."}
            </p>

            <form ref={formRef} onSubmit={handleSubmit} className="mt-7 space-y-4" noValidate>
              <div>
                <label
                  htmlFor="email"
                  className="mb-1.5 block font-mono text-[10px] uppercase tracking-[0.22em] text-text-dim"
                >
                  Email
                </label>
                <input
                  id="email"
                  type="email"
                  autoComplete="email"
                  required
                  value={email}
                  onChange={(event) => setEmail(event.target.value)}
                  placeholder="analyst@org.com"
                  aria-invalid={email.length > 0 && !emailValid}
                  aria-describedby="email-hint"
                  className={fieldClass}
                  style={{
                    borderColor:
                      email.length === 0
                        ? "var(--color-border-dim)"
                        : emailValid
                          ? "rgba(0,245,255,0.5)"
                          : "rgba(255,215,0,0.45)",
                  }}
                />
                {/* Say WHY it is not accepted. A field that just refuses to turn
                    green, next to a button that will not enable, leaves the
                    reader with nothing to act on. */}
                <AnimatePresence>
                  {email.length > 0 && !emailValid && (
                    <motion.p
                      id="email-hint"
                      initial={{ opacity: 0, height: 0 }}
                      animate={{ opacity: 1, height: "auto" }}
                      exit={{ opacity: 0, height: 0 }}
                      className="overflow-hidden pt-1.5 font-mono text-[11px] text-amber"
                    >
                      Needs the full form — name@domain.com
                    </motion.p>
                  )}
                </AnimatePresence>
              </div>

              <div>
                <label
                  htmlFor="password"
                  className="mb-1.5 block font-mono text-[10px] uppercase tracking-[0.22em] text-text-dim"
                >
                  Password
                </label>
                <div className="relative">
                  <input
                    id="password"
                    type={showPassword ? "text" : "password"}
                    autoComplete={isSignup ? "new-password" : "current-password"}
                    required
                    value={password}
                    onChange={(event) => setPassword(event.target.value)}
                    placeholder={isSignup ? `At least ${MIN_PASSWORD_LENGTH} characters` : "••••••••••••"}
                    className={`${fieldClass} pr-11`}
                    style={{
                      borderColor:
                        password.length === 0
                          ? "var(--color-border-dim)"
                          : passwordValid
                            ? "rgba(0,255,136,0.5)"
                            : "rgba(255,215,0,0.45)",
                    }}
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword((value) => !value)}
                    aria-label={showPassword ? "Hide password" : "Show password"}
                    className="absolute right-2.5 top-1/2 -translate-y-1/2 rounded p-1 text-text-dim outline-none transition-colors hover:text-cyan focus-visible:text-cyan"
                  >
                    {showPassword ? <EyeSlash size={15} /> : <Eye size={15} />}
                  </button>
                </div>

                {isSignup && (
                  <>
                    <div className="mt-2 h-0.5 w-full overflow-hidden rounded-full bg-border-dim">
                      <motion.div
                        className="h-full rounded-full"
                        animate={{
                          width: `${passwordStrength * 100}%`,
                          backgroundColor: passwordValid ? ACCENT.green : "#ffd700",
                        }}
                        transition={{ duration: 0.25, ease: "easeOut" }}
                      />
                    </div>
                    {/* Count down the exact shortfall rather than restating the
                        rule - the reader can see how far they still have to go. */}
                    <p className="pt-1.5 font-mono text-[11px] text-text-dim">
                      {password.length === 0
                        ? `${MIN_PASSWORD_LENGTH} characters minimum`
                        : passwordValid
                          ? "Long enough"
                          : `${MIN_PASSWORD_LENGTH - password.length} more character${
                              MIN_PASSWORD_LENGTH - password.length === 1 ? "" : "s"
                            } needed`}
                    </p>
                  </>
                )}
              </div>

              <AnimatePresence>
                {error && (
                  <motion.p
                    role="alert"
                    initial={{ opacity: 0, height: 0 }}
                    animate={{ opacity: 1, height: "auto" }}
                    exit={{ opacity: 0, height: 0 }}
                    className="flex items-start gap-2 overflow-hidden rounded-lg border border-red/30 bg-red/10 px-3 py-2 text-[13px] text-red"
                  >
                    <WarningCircle size={15} weight="bold" className="mt-px shrink-0" />
                    {error}
                  </motion.p>
                )}
              </AnimatePresence>

              <motion.button
                type="submit"
                disabled={!ready}
                whileTap={ready ? { scale: 0.985 } : undefined}
                className="group/submit flex w-full items-center justify-center gap-2 rounded-lg border px-4 py-3 font-mono text-xs uppercase tracking-[0.15em] outline-none transition-all disabled:cursor-not-allowed"
                style={{
                  borderColor: ready ? "rgba(0,245,255,0.55)" : "var(--color-border-dim)",
                  color: ready ? ACCENT.cyan : "var(--color-text-dim)",
                  background: ready
                    ? "linear-gradient(140deg, rgba(0,245,255,0.16) 0%, rgba(13,14,23,0.7) 70%)"
                    : "transparent",
                  boxShadow: ready ? "0 0 30px -10px rgba(0,245,255,0.55)" : "none",
                }}
              >
                {submitting ? (
                  <>
                    <span className="h-3.5 w-3.5 animate-spin rounded-full border-2 border-cyan/25 border-t-cyan" />
                    {isSignup ? "Creating" : "Verifying"}
                  </>
                ) : (
                  <>
                    {isSignup ? "Create account" : "Open console"}
                    <ArrowRight
                      size={13}
                      weight="bold"
                      className="transition-transform duration-200 group-hover/submit:translate-x-0.5"
                    />
                  </>
                )}
              </motion.button>

              {/* A disabled button with no explanation is a dead end. Name the
                  one thing still outstanding, so the fix is obvious. */}
              <AnimatePresence>
                {blockedReason && (
                  <motion.p
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    exit={{ opacity: 0 }}
                    className="text-center font-mono text-[11px] text-text-dim"
                    aria-live="polite"
                  >
                    {blockedReason}
                  </motion.p>
                )}
              </AnimatePresence>
            </form>

            <p className="mt-6 text-center font-mono text-[11px] text-text-dim">
              {isSignup ? "Already have access?" : "No credentials yet?"}{" "}
              <Link
                to={isSignup ? "/login" : "/signup"}
                className="text-cyan underline-offset-2 hover:underline"
              >
                {isSignup ? "Sign in" : "Request access"}
              </Link>
            </p>
          </div>
        </div>
      </motion.div>
    </div>
  );
}
