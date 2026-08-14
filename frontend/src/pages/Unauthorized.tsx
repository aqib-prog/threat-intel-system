import { Link } from "react-router-dom";
import { motion } from "framer-motion";
import { ArrowRight, LockKey } from "@phosphor-icons/react";
import { AuthBackdrop } from "../components/auth/AuthBackdrop";
import { useReducedMotion } from "../hooks/useReducedMotion";

/**
 * The refusal screen.
 *
 * Deliberately not an apology or an error dump. A denied request is the system
 * working correctly, so this reads as a sealed door rather than a failure: the
 * status is stated plainly, the reason is given, and the way forward is the
 * loudest thing on screen.
 */
export function Unauthorized() {
  const reduced = useReducedMotion();

  return (
    <div className="relative flex min-h-dvh items-center justify-center px-5 py-12">
      <AuthBackdrop />

      <motion.div
        initial={{ opacity: 0, y: 16 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5, ease: [0.16, 1, 0.3, 1] }}
        className="relative z-10 w-full max-w-lg overflow-hidden rounded-2xl border border-red/25 px-8 py-11 text-center"
        style={{
          background:
            "linear-gradient(150deg, rgba(255,51,102,0.09) 0%, rgba(10,10,18,0.95) 45%, rgba(124,58,237,0.06) 100%), rgba(8,8,14,0.97)",
          boxShadow:
            "inset 0 1px 0 rgba(255,255,255,0.12), 0 40px 90px -44px rgba(255,51,102,0.5)",
        }}
      >
        {/* Sealed lock: rings pulse outward and are absorbed, so the barrier
            reads as actively held rather than statically drawn. */}
        <div className="relative mx-auto mb-7 flex h-24 w-24 items-center justify-center">
          {!reduced &&
            [0, 1].map((index) => (
              <motion.span
                key={index}
                className="absolute rounded-full border border-red/40"
                style={{ width: 96, height: 96 }}
                animate={{ scale: [0.55, 1.35], opacity: [0.5, 0] }}
                transition={{
                  duration: 2.6,
                  repeat: Infinity,
                  delay: index * 1.3,
                  ease: "easeOut",
                }}
              />
            ))}
          <motion.span
            className="relative flex h-16 w-16 items-center justify-center rounded-full border border-red/40 text-red"
            style={{ background: "rgba(255,51,102,0.10)" }}
            animate={reduced ? undefined : { scale: [1, 1.05, 1] }}
            transition={{ duration: 2.6, repeat: Infinity, ease: "easeInOut" }}
          >
            <LockKey size={26} weight="bold" aria-hidden="true" />
          </motion.span>
        </div>

        <p className="font-mono text-[10px] uppercase tracking-[0.3em] text-red">
          401 · Access denied
        </p>
        <h1 className="mt-3 font-display text-2xl font-semibold tracking-tight text-white">
          This console is sealed
        </h1>
        <p className="mx-auto mt-3 max-w-sm text-sm leading-relaxed text-text-mid">
          The knowledge graph is only served to an authenticated session. Your
          request reached the system and was refused — nothing was returned.
        </p>

        <div className="mt-8 flex flex-col items-center gap-3 sm:flex-row sm:justify-center">
          <Link
            to="/login"
            className="group/act inline-flex w-full items-center justify-center gap-2 rounded-lg border border-cyan/45 px-5 py-2.5 font-mono text-xs uppercase tracking-[0.15em] text-cyan no-underline transition-colors hover:border-cyan sm:w-auto"
            style={{
              background: "linear-gradient(140deg, rgba(0,245,255,0.14) 0%, rgba(13,14,23,0.7) 70%)",
              boxShadow: "0 0 28px -12px rgba(0,245,255,0.6)",
            }}
          >
            Authenticate
            <ArrowRight
              size={13}
              weight="bold"
              className="transition-transform duration-200 group-hover/act:translate-x-0.5"
            />
          </Link>
          <Link
            to="/"
            className="font-mono text-[11px] uppercase tracking-[0.15em] text-text-dim no-underline transition-colors hover:text-text-mid"
          >
            Back to overview
          </Link>
        </div>
      </motion.div>
    </div>
  );
}
