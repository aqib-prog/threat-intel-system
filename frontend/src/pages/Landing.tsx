import { lazy, Suspense } from "react";
import { motion } from "framer-motion";
import { BackgroundStack } from "../components/effects/BackgroundStack";
import { MitreBadges } from "../components/landing/MitreBadges";
import { GlitchTitle } from "../components/landing/GlitchTitle";
import { StatCard } from "../components/landing/StatCard";
import { StatCardSkeleton } from "../components/landing/StatCardSkeleton";
import { LaunchButton } from "../components/landing/LaunchButton";
import { SiteFooter } from "../components/landing/SiteFooter";
import { Logo } from "../components/shared/Logo";
import { useLiveStats } from "../hooks/useLiveStats";
import { useSmoothScroll } from "../hooks/useSmoothScroll";

const Globe = lazy(() => import("../components/landing/Globe").then((m) => ({ default: m.Globe })));
const ScrollDismantle = lazy(() =>
  import("../components/landing/ScrollDismantle").then((m) => ({ default: m.ScrollDismantle }))
);
const PipelineFlow = lazy(() =>
  import("../components/landing/PipelineFlow").then((m) => ({ default: m.PipelineFlow }))
);
const ScrollVideo = lazy(() =>
  import("../components/landing/ScrollVideo").then((m) => ({ default: m.ScrollVideo }))
);

export function Landing() {
  const { stats, isFallback, loading } = useLiveStats();
  // Marketing surface only - the chat route keeps native scrolling.
  useSmoothScroll();

  return (
    // No overflow-hidden here: it would break `position: sticky` in the
    // scroll-scrubbed sections below. BackgroundStack already renders its own
    // `fixed inset-0` layer, so it must NOT be wrapped again - the extra
    // wrapper made the ambient canvases size themselves against the document
    // instead of the viewport, which is what tanked scroll performance.
    <div className="relative bg-void">
      <BackgroundStack />
      <MitreBadges />

      <header className="relative z-10 flex items-center justify-between px-6 py-6 sm:px-10">
        <Logo />
        <a
          href="https://attack.mitre.org"
          target="_blank"
          rel="noreferrer"
          className="hidden font-mono text-xs tracking-wider text-text-mid transition-colors hover:text-cyan sm:block"
        >
          DOCS
        </a>
      </header>

      <main className="relative z-10 mx-auto grid max-w-[96rem] grid-cols-1 items-center gap-8 px-6 pb-16 pt-8 sm:px-10 lg:grid-cols-[minmax(760px,1.05fr)_minmax(420px,0.95fr)] lg:gap-10 lg:pt-4 xl:gap-14">
        <div className="order-2 lg:order-1">
          <motion.p
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ delay: 0.15, duration: 0.6 }}
            className="mb-4 font-mono text-xs uppercase tracking-[0.3em] text-green"
          >
            <span className="mr-2 inline-block h-1.5 w-1.5 rounded-full bg-green motion-safe:animate-pulse" />
            Graph RAG Threat Intelligence
          </motion.p>

          <GlitchTitle text="THREAT INTEL AI" />

          <motion.p
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.3, duration: 0.6 }}
            className="mt-5 max-w-lg font-mono text-sm text-text-mid sm:text-base"
          >
            Powered by Graph RAG + MITRE ATT&CK. Query a live knowledge graph
            of adversary tactics, techniques, and threat actors — grounded,
            cited, and guarded against hallucination.
          </motion.p>

          <div className="mt-9">
            <LaunchButton />
          </div>

          <div className="mt-14 grid max-w-[66rem] grid-cols-1 gap-5 sm:grid-cols-3">
            {loading || !stats ? (
              <>
                <StatCardSkeleton />
                <StatCardSkeleton />
                <StatCardSkeleton />
              </>
            ) : (
              <>
                <StatCard
                  value={stats.node_count}
                  label="Nodes Indexed"
                  accent="cyan"
                  delay={0}
                />
                <StatCard
                  value={stats.relationship_count}
                  label="Relationships"
                  accent="green"
                  delay={0.1}
                />
                <StatCard
                  value={stats.tactic_count}
                  label="Tactics Mapped"
                  accent="purple"
                  delay={0.2}
                />
              </>
            )}
          </div>

          {!loading && isFallback && (
            <p className="mt-3 font-mono text-[10px] uppercase tracking-wider text-amber/80">
              ⚠ estimated · last known snapshot, backend unreachable
            </p>
          )}
        </div>

        <div className="order-1 h-[280px] sm:h-[380px] lg:order-2 lg:h-[560px]">
          <Suspense fallback={<div className="h-full w-full animate-pulse rounded-full" />}>
            <Globe />
          </Suspense>
        </div>
      </main>

      <Suspense fallback={<div className="h-dvh" />}>
        <ScrollVideo />
      </Suspense>

      <Suspense fallback={<div className="h-dvh" />}>
        <ScrollDismantle />
      </Suspense>

      <Suspense fallback={<div className="h-96" />}>
        <PipelineFlow />
      </Suspense>

      <SiteFooter />
    </div>
  );
}
