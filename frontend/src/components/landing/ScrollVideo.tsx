import { useLayoutEffect, useRef, useState } from "react";
import gsap from "gsap";
import { ScrollTrigger } from "gsap/ScrollTrigger";
import { useReducedMotion } from "../../hooks/useReducedMotion";

gsap.registerPlugin(ScrollTrigger);

/**
 * Scroll-scrubbed hero film.
 *
 * Scroll position drives the video's `currentTime` directly, so the reader
 * scrubs the footage frame by frame - forward and backward - exactly the way a
 * product page dismantles a device as you scroll. The clip is encoded all-intra
 * (a keyframe on every frame) specifically for this: seeking a normally-encoded
 * H.264 file lands on the nearest keyframe and the picture visibly stutters.
 *
 * The video is never played. It is only ever seeked, which keeps it in lockstep
 * with the scroll instead of racing ahead on its own clock.
 */

interface Caption {
  at: number; // scroll progress 0-1 where this caption takes over
  kicker: string;
  line: string;
}

const CAPTIONS: Caption[] = [
  { at: 0, kicker: "4,368 entities", line: "Every actor, technique, and campaign, connected." },
  { at: 0.34, kicker: "15 relationship types", line: "Answers travel the graph, not a similarity score." },
  { at: 0.68, kicker: "Grounded by construction", line: "If an ID isn't in the graph, it never reaches you." },
];

export function ScrollVideo() {
  const sectionRef = useRef<HTMLElement>(null);
  const videoRef = useRef<HTMLVideoElement>(null);
  const reduced = useReducedMotion();
  const [active, setActive] = useState(0);

  useLayoutEffect(() => {
    if (reduced) return; // poster frame only; no scroll hijack, no seeking
    const context = gsap.context(() => {
      const video = videoRef.current;
      const section = sectionRef.current;
      if (!video || !section) return;

      // A proxy object is tweened rather than the element: GSAP interpolates the
      // time value, and each frame we write it to the video. Writing currentTime
      // directly from a scroll handler would seek far more often than the
      // decoder can service.
      const state = { time: 0 };

      const build = () => {
        const duration = video.duration;
        if (!duration || Number.isNaN(duration)) return;
        gsap.to(state, {
          time: duration,
          ease: "none",
          scrollTrigger: {
            trigger: section,
            start: "top top",
            end: "bottom bottom",
            scrub: 0.35,
            onUpdate: (self) => {
              // Captions are keyed to scroll progress, not to video time, so
              // they stay put if the decoder lags behind a fast flick.
              let next = 0;
              for (let i = 0; i < CAPTIONS.length; i += 1) {
                if (self.progress >= CAPTIONS[i].at) next = i;
              }
              setActive(next);
            },
          },
          onUpdate: () => {
            // Guard the seek: an out-of-range or NaN write throws in Safari.
            const t = Math.min(Math.max(state.time, 0), duration - 0.02);
            if (Number.isFinite(t)) video.currentTime = t;
          },
        });
        // Metadata can land after layout, so positions are recalculated once
        // the real duration is known.
        ScrollTrigger.refresh();
      };

      if (video.readyState >= 1) build();
      else video.addEventListener("loadedmetadata", build, { once: true });
    }, sectionRef);

    return () => context.revert();
  }, [reduced]);

  return (
    <section ref={sectionRef} className="relative z-10 h-[320vh]">
      <div className="sticky top-0 h-dvh w-full overflow-hidden">
        <video
          ref={videoRef}
          className="absolute inset-0 h-full w-full object-cover"
          src="/video/hero-scrub.mp4"
          poster="/video/hero-poster.jpg"
          muted
          playsInline
          // "auto" pulled the whole 5.4 MB clip during initial page load and
          // competed with first paint. Metadata is enough to build the scrub
          // (we only need duration); frames stream in as the section is reached.
          preload="metadata"
          // Decorative: the captions beside it carry the meaning.
          aria-hidden="true"
          tabIndex={-1}
        />

        {/* Legibility scrim - the footage is bright in the centre. */}
        <div
          aria-hidden="true"
          className="absolute inset-0"
          style={{
            background:
              "linear-gradient(90deg, rgba(5,5,8,0.94) 0%, rgba(5,5,8,0.72) 38%, rgba(5,5,8,0.25) 70%, rgba(5,5,8,0.6) 100%)",
          }}
        />

        <div className="relative flex h-full items-center">
          <div className="mx-auto w-full max-w-[96rem] px-6 sm:px-10">
            <div className="max-w-lg">
              <p className="font-mono text-xs uppercase tracking-[0.3em] text-cyan">
                {CAPTIONS[active].kicker}
              </p>
              <p className="mt-4 font-display text-3xl font-semibold leading-tight text-white sm:text-4xl">
                {CAPTIONS[active].line}
              </p>

              {/* Which beat of the film you're on. */}
              <div className="mt-8 flex gap-2">
                {CAPTIONS.map((caption, i) => (
                  <span
                    key={caption.at}
                    className="h-px w-12 transition-colors duration-300"
                    style={{
                      background: i <= active ? "var(--color-cyan)" : "var(--color-border-dim)",
                      boxShadow: i === active ? "0 0 10px rgba(0,245,255,0.8)" : undefined,
                    }}
                  />
                ))}
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
