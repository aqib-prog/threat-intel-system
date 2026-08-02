import { useEffect } from "react";
import Lenis from "lenis";
import gsap from "gsap";
import { ScrollTrigger } from "gsap/ScrollTrigger";

gsap.registerPlugin(ScrollTrigger);

/**
 * Momentum ("smooth") scrolling for the marketing surface.
 *
 * Two things make scroll-scrubbed sequences feel expensive rather than jerky:
 * inertia on the scroll position itself, and driving it from the same clock
 * that runs the animations. Lenis supplies the inertia; ticking it from GSAP's
 * ticker (instead of its own rAF loop) keeps scrub updates on the exact frame
 * the tweens render, which removes the shimmer you get when the two loops drift.
 *
 * Disabled entirely under prefers-reduced-motion: hijacking scroll is the most
 * disorienting thing you can do to someone who asked for less motion.
 */
export function useSmoothScroll(enabled = true) {
  useEffect(() => {
    if (!enabled) return;
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;

    const lenis = new Lenis({
      duration: 1.05,
      // Exponential ease-out: fast pickup, long settle - the curve that reads
      // as weight rather than lag.
      easing: (t: number) => Math.min(1, 1.001 - Math.pow(2, -10 * t)),
      smoothWheel: true,
      // Touch devices already have native momentum; overriding it feels wrong.
      syncTouch: false,
    });

    lenis.on("scroll", ScrollTrigger.update);

    const tick = (time: number) => lenis.raf(time * 1000);
    gsap.ticker.add(tick);
    gsap.ticker.lagSmoothing(0);

    return () => {
      gsap.ticker.remove(tick);
      lenis.destroy();
    };
  }, [enabled]);
}
