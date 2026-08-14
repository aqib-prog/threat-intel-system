import { useCallback, useEffect, useLayoutEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { AnimatePresence, motion } from "framer-motion";
import { SignOut, UserCircle } from "@phosphor-icons/react";
import { useAuth } from "../../hooks/useAuth";

/**
 * Who is signed in, and how to stop being signed in.
 *
 * Without this the session was invisible: the only way to tell whether you had
 * one was to see whether the app worked, and the only way to end it was to wait
 * two days for it to expire. Both are basic expectations of any signed-in app.
 */
export function SessionMenu() {
  const { user, signOut } = useAuth();
  const [open, setOpen] = useState(false);
  const [signingOut, setSigningOut] = useState(false);
  const containerRef = useRef<HTMLDivElement>(null);
  const triggerRef = useRef<HTMLButtonElement>(null);
  const menuRef = useRef<HTMLDivElement>(null);
  const [anchor, setAnchor] = useState<{ top: number; right: number } | null>(null);

  // The menu is rendered into document.body.
  //
  // The navbar lives inside a `z-10` wrapper, and a positioned ancestor creates
  // a stacking context - so the menu's own z-50 only ever applied INSIDE that
  // context, leaving it beneath the page's z-40 scanline overlay. A portal puts
  // it at the top level where nothing can sit above it, and fixed positioning
  // keeps it pinned to the trigger.
  const reposition = useCallback(() => {
    const trigger = triggerRef.current;
    if (!trigger) return;
    const rect = trigger.getBoundingClientRect();
    setAnchor({ top: rect.bottom + 8, right: window.innerWidth - rect.right });
  }, []);

  useLayoutEffect(() => {
    if (open) reposition();
  }, [open, reposition]);

  useEffect(() => {
    if (!open) return;
    const onChange = () => reposition();
    window.addEventListener("resize", onChange);
    window.addEventListener("scroll", onChange, true);
    return () => {
      window.removeEventListener("resize", onChange);
      window.removeEventListener("scroll", onChange, true);
    };
  }, [open, reposition]);

  useEffect(() => {
    if (!open) return;
    const onPointerDown = (event: PointerEvent) => {
      const target = event.target as Node | null;
      // Only an genuinely outside press closes the menu. Without this check the
      // same press that lands on "Sign out" also unmounts the button, and the
      // click that would have run the handler never arrives.
      // The menu now lives outside containerRef (it is portalled), so both
      // roots have to be treated as "inside".
      if (target && containerRef.current?.contains(target)) return;
      if (target && menuRef.current?.contains(target)) return;
      setOpen(false);
    };
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") setOpen(false);
    };
    window.addEventListener("pointerdown", onPointerDown);
    window.addEventListener("keydown", onKey);
    return () => {
      window.removeEventListener("pointerdown", onPointerDown);
      window.removeEventListener("keydown", onKey);
    };
  }, [open]);

  if (!user) return null;

  const handleSignOut = async () => {
    if (signingOut) return; // ignore a double click mid-flight
    setSigningOut(true);
    try {
      await signOut();
    } finally {
      // A FULL page load, not client-side navigation.
      //
      // Signing out must leave nothing behind: an in-app navigate keeps every
      // React state tree, cached hook, and in-memory copy of the previous
      // user alive, and any one of them re-rendering with a stale value can
      // make the sign-out look like it did nothing. Replacing the document
      // guarantees the next screen starts from zero, and `replace` keeps the
      // signed-in page out of the back history.
      window.location.replace("/login");
    }
  };

  // Local part only - the full address is in the menu. A navbar is not the
  // place to display someone's whole email to anyone glancing at the screen.
  const shortName = user.email.split("@")[0];

  return (
    <div ref={containerRef} className="relative">
      <button
        ref={triggerRef}
        type="button"
        onClick={() => setOpen((value) => !value)}
        aria-haspopup="menu"
        aria-expanded={open}
        aria-label={`Signed in as ${user.email}. Open account menu.`}
        className="flex cursor-pointer items-center gap-1.5 rounded-full border border-cyan/25 py-1 pl-1 pr-2.5 outline-none transition-colors hover:border-cyan/50 focus-visible:border-cyan"
        style={{ background: "rgba(0,245,255,0.07)" }}
      >
        <span className="flex h-5 w-5 items-center justify-center rounded-full bg-cyan/15 text-cyan">
          <UserCircle size={13} weight="bold" aria-hidden="true" />
        </span>
        <span className="max-w-[9rem] truncate font-mono text-[11px] text-cyan">{shortName}</span>
      </button>

      {createPortal(
        <AnimatePresence>
        {open && anchor && (
          <motion.div
            ref={menuRef}
            role="menu"
            initial={{ opacity: 0, y: -6, scale: 0.97 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: -4, scale: 0.98 }}
            transition={{ duration: 0.16, ease: [0.16, 1, 0.3, 1] }}
            className="w-60 overflow-hidden rounded-xl border border-cyan/20"
            style={{
              position: "fixed",
              top: anchor.top,
              right: anchor.right,
              zIndex: 200,
              background:
                "linear-gradient(150deg, rgba(0,245,255,0.08) 0%, rgba(10,10,18,0.97) 45%)",
              boxShadow:
                "inset 0 1px 0 rgba(255,255,255,0.12), 0 24px 50px -26px rgba(0,245,255,0.5)",
            }}
          >
            <div className="border-b border-border-dim px-3.5 py-3">
              <p className="font-mono text-[9px] uppercase tracking-[0.25em] text-text-dim">
                Signed in as
              </p>
              <p className="mt-1 truncate text-[13px] text-white">{user.email}</p>
              <p className="mt-2 flex items-center gap-1.5 font-mono text-[10px] text-text-dim">
                <span className="inline-block h-1.5 w-1.5 rounded-full bg-green motion-safe:animate-pulse" />
                Session active
              </p>
            </div>

            <button
              type="button"
              role="menuitem"
              onClick={handleSignOut}
              disabled={signingOut}
              className="group/out flex w-full cursor-pointer items-center gap-2 px-3.5 py-2.5 text-left font-mono text-xs text-red outline-none transition-colors hover:bg-red/10 focus-visible:bg-red/10 disabled:opacity-60"
            >
              {signingOut ? (
                <span className="h-3.5 w-3.5 animate-spin rounded-full border-2 border-red/25 border-t-red" />
              ) : (
                <SignOut
                  size={13}
                  weight="bold"
                  aria-hidden="true"
                  className="transition-transform duration-200 group-hover/out:translate-x-0.5"
                />
              )}
              {signingOut ? "Signing out" : "Sign out"}
            </button>
          </motion.div>
        )}
        </AnimatePresence>,
        document.body
      )}
    </div>
  );
}
