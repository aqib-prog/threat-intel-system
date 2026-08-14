import { lazy, Suspense } from "react";
import { Routes, Route, Navigate, useLocation } from "react-router-dom";
import { AnimatePresence, motion } from "framer-motion";
import { AuthProvider, useAuth } from "./hooks/useAuth";
// Eager, not lazy: this is the destination every authenticated session lands
// on, and behind the route guard a suspending child left AnimatePresence
// holding an empty shell whose chunk was never requested.
import { Chat } from "./pages/Chat";

const Landing = lazy(() => import("./pages/Landing").then((m) => ({ default: m.Landing })));
const NotFound = lazy(() => import("./pages/NotFound").then((m) => ({ default: m.NotFound })));
const AuthPage = lazy(() => import("./pages/AuthPage").then((m) => ({ default: m.AuthPage })));
const Unauthorized = lazy(() =>
  import("./pages/Unauthorized").then((m) => ({ default: m.Unauthorized }))
);

// Opacity only - deliberately NO scale/transform.
//
// Framer Motion writes `scale` as a CSS transform, and a transformed ancestor
// becomes the containing block for every `position: fixed` descendant. That
// silently turned the landing page's fixed full-screen background layer into a
// page-height element, so its canvases sized themselves to the whole document
// (~21 megapixels) and repainted that every frame. Keeping this transform-free
// is what lets `fixed` mean "viewport" again.
// Fade IN only - deliberately no `exit`.
//
// An exit animation keeps the outgoing route mounted for its whole duration, so
// the landing page's WebGL globe and two canvases were still live while the chat
// mounted its own canvas and video. That overlap is what made the hand-off
// stutter; no easing curve can hide two GPU scenes competing for one frame.
// Without an exit the old tree is released immediately and only the incoming
// page is doing work, which is what actually makes the change feel instant.
const pageTransition = {
  initial: { opacity: 0 },
  animate: { opacity: 1 },
};

function AnimatedPage({ children }: { children: React.ReactNode }) {
  return (
    <motion.div
      initial={pageTransition.initial}
      animate={pageTransition.animate}
      // Short and eased-out: long enough to avoid a hard cut, short enough that
      // it never competes with the incoming page's own first paint.
      transition={{ duration: 0.22, ease: [0.16, 1, 0.3, 1] }}
    >
      {/* Suspense sits INSIDE the animated element, not around <AnimatePresence>.
          With it outside, a lazy route suspending replaced AnimatePresence's
          keyed child with the fallback; `mode="wait"` then held the transition
          open and the route mounted as an empty shell whose chunk was never
          even requested. Boundary here means the page element mounts
          immediately and only its CONTENT waits. */}
      <Suspense fallback={<div className="min-h-dvh bg-void" />}>{children}</Suspense>
    </motion.div>
  );
}

/**
 * Boot screen shown while the initial session check is in flight.
 *
 * Deliberately rendered ABOVE <AnimatePresence>. When the guard's own loading
 * state lived inside it, resolving the session swapped the keyed child
 * mid-transition; `mode="wait"` then held the outgoing subtree waiting for an
 * exit animation, and the incoming route mounted as an empty shell - its lazy
 * chunk was never even requested. Resolving auth first means every route mounts
 * exactly once, and there is no unauthenticated flash before a redirect.
 */
function SessionBoot() {
  return (
    <div className="flex min-h-dvh items-center justify-center bg-void">
      <div className="flex flex-col items-center gap-3">
        <span className="h-6 w-6 animate-spin rounded-full border-2 border-cyan/25 border-t-cyan" />
        <p className="font-mono text-[11px] uppercase tracking-[0.25em] text-text-dim">
          Establishing session
        </p>
      </div>
    </div>
  );
}

function AppRoutes() {
  const location = useLocation();
  const { loading, user } = useAuth();

  if (loading) return <SessionBoot />;

  // Deliberately NO `mode="wait"`, and this was re-tested rather than assumed.
  //
  // It was tried again to smooth the landing -> chat transition and it broke the
  // app a second time: a route that redirects (the /chat guard rendering
  // <Navigate>) changes location while the previous page is still animating out,
  // and `mode="wait"` queues the incoming page behind an exit that never
  // completes - leaving BOTH /chat and /login mounted but empty. Cross-fading
  // costs a brief overlap; deadlocking costs the whole page.
  return (
      <AnimatePresence>
          <Routes location={location} key={location.pathname}>
            <Route
              path="/"
              element={
                <AnimatedPage>
                  <Landing />
                </AnimatedPage>
              }
            />
            <Route
              path="/login"
              element={
                <AnimatedPage>
                  <AuthPage mode="login" />
                </AnimatedPage>
              }
            />
            <Route
              path="/signup"
              element={
                <AnimatedPage>
                  <AuthPage mode="signup" />
                </AnimatedPage>
              }
            />
            <Route
              path="/unauthorized"
              element={
                <AnimatedPage>
                  <Unauthorized />
                </AnimatedPage>
              }
            />
            {/* Gated at the ROUTE, not via a wrapper component.
                A guard component between <Routes> and the animated element
                added a boundary inside `AnimatePresence mode="wait"` that left
                the page mounted but empty - verified by bypassing it, which
                made the identical tree render. Deciding here keeps one element
                per route, which is what AnimatePresence expects.

                This is UX only: every protected endpoint is independently
                enforced server-side, so bypassing it changes nothing about
                what the backend returns. */}
            <Route
              path="/chat"
              element={
                // The guard lives INSIDE the animated element, never around it.
                // Swapping <AnimatedPage> for a bare <Navigate> (which renders
                // null) left `mode="wait"` waiting forever for an exit that
                // could not happen, and the page mounted empty.
                <AnimatedPage>
                  {user ? (
                    <Chat />
                  ) : (
                    <Navigate to="/login" replace state={{ from: location }} />
                  )}
                </AnimatedPage>
              }
            />
            <Route
              path="*"
              element={
                <AnimatedPage>
                  <NotFound />
                </AnimatedPage>
              }
            />
          </Routes>
      </AnimatePresence>
  );
}

function App() {
  return (
    <AuthProvider>
      <AppRoutes />
    </AuthProvider>
  );
}

export default App;
