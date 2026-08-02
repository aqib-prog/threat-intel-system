import { lazy, Suspense } from "react";
import { Routes, Route, useLocation } from "react-router-dom";
import { AnimatePresence, motion } from "framer-motion";

const Landing = lazy(() => import("./pages/Landing").then((m) => ({ default: m.Landing })));
const Chat = lazy(() => import("./pages/Chat").then((m) => ({ default: m.Chat })));
const NotFound = lazy(() => import("./pages/NotFound").then((m) => ({ default: m.NotFound })));

// Opacity only - deliberately NO scale/transform.
//
// Framer Motion writes `scale` as a CSS transform, and a transformed ancestor
// becomes the containing block for every `position: fixed` descendant. That
// silently turned the landing page's fixed full-screen background layer into a
// page-height element, so its canvases sized themselves to the whole document
// (~21 megapixels) and repainted that every frame. Keeping this transform-free
// is what lets `fixed` mean "viewport" again.
const pageTransition = {
  initial: { opacity: 0 },
  animate: { opacity: 1 },
  exit: { opacity: 0 },
};

function AnimatedPage({ children }: { children: React.ReactNode }) {
  return (
    <motion.div
      initial={pageTransition.initial}
      animate={pageTransition.animate}
      exit={pageTransition.exit}
      transition={{ duration: 0.35, ease: "easeInOut" }}
    >
      {children}
    </motion.div>
  );
}

function App() {
  const location = useLocation();

  return (
    <Suspense fallback={<div className="min-h-dvh bg-void" />}>
      <AnimatePresence mode="wait">
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
            path="/chat"
            element={
              <AnimatedPage>
                <Chat />
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
    </Suspense>
  );
}

export default App;
