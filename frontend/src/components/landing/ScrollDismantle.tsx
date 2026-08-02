import { useLayoutEffect, useRef, useState } from "react";
import gsap from "gsap";
import { ScrollTrigger } from "gsap/ScrollTrigger";
import { useReducedMotion } from "../../hooks/useReducedMotion";

gsap.registerPlugin(ScrollTrigger);

/**
 * Scroll-scrubbed exploded view: "Anatomy of an intrusion".
 *
 * The same interaction pattern as a product page that dismantles a device as
 * you scroll - except the thing being taken apart is a compromised environment.
 * Scroll position drives the separation directly (GSAP ScrollTrigger `scrub`),
 * so the user scrubs the sequence forward and backward exactly like video
 * frames; the layers are rendered live in CSS 3D rather than decoded from a
 * file, which keeps it sharp at any viewport and needs no asset download.
 *
 * Each plate is one layer of a real defensive stack, paired with the ATT&CK
 * tactic that targets it - so pulling the stack apart teaches the kill chain
 * instead of just looking kinetic.
 */

interface Layer {
  label: string;
  tacticId: string;
  tactic: string;
  detail: string;
}

const LAYERS: Layer[] = [
  { label: "Network edge", tacticId: "TA0001", tactic: "Initial Access", detail: "Exposed service or a link someone trusted" },
  { label: "Endpoint", tacticId: "TA0002", tactic: "Execution", detail: "Attacker code runs as a normal process" },
  { label: "Process memory", tacticId: "TA0004", tactic: "Privilege Escalation", detail: "Token theft and injection raise access" },
  { label: "Credential store", tacticId: "TA0006", tactic: "Credential Access", detail: "Secrets pulled from memory and disk" },
  { label: "Identity plane", tacticId: "TA0008", tactic: "Lateral Movement", detail: "Valid accounts carry the intrusion sideways" },
  { label: "Data", tacticId: "TA0010", tactic: "Exfiltration", detail: "Collected data leaves over the C2 channel" },
];

const SPREAD = 108; // px of separation per plate at full scrub

export function ScrollDismantle() {
  const sectionRef = useRef<HTMLElement>(null);
  const stackRef = useRef<HTMLDivElement>(null);
  const plateRefs = useRef<(HTMLDivElement | null)[]>([]);
  const cardRefs = useRef<(HTMLDivElement | null)[]>([]);
  const reduced = useReducedMotion();
  const [progress, setProgress] = useState(0);

  useLayoutEffect(() => {
    const context = gsap.context(() => {
      const plates = plateRefs.current.filter(Boolean) as HTMLDivElement[];
      const cards = cardRefs.current.filter(Boolean) as HTMLDivElement[];
      if (!plates.length) return;

      if (reduced) {
        // No scrub: present the stack already separated and fully labelled.
        plates.forEach((plate, i) => {
          gsap.set(plate, { z: (LAYERS.length - 1 - i) * SPREAD * 0.6 });
        });
        gsap.set(cards, { opacity: 1, x: 0 });
        setProgress(1);
        return;
      }

      gsap.set(cards, { opacity: 0, x: -18 });

      // Total lift has to fit the space left under the heading, or the top
      // plate climbs over the copy on short/narrow viewports.
      const spread = Math.max(
        44,
        Math.min(SPREAD, (window.innerHeight - 340) / (LAYERS.length - 1))
      );

      const timeline = gsap.timeline({
        scrollTrigger: {
          trigger: sectionRef.current,
          start: "top top",
          end: "bottom bottom",
          scrub: 0.6,
          onUpdate: (self) => setProgress(self.progress),
        },
      });

      // The stack tilts toward the viewer as it comes apart, so separation
      // reads as depth rather than a list sliding down the page. It also drifts
      // downward by roughly half the total lift: plates rise as they separate,
      // so without this the exploded group climbs into the heading above it.
      timeline.fromTo(
        stackRef.current,
        { rotationX: 64, rotation: -10, y: 0 },
        { rotationX: 46, rotation: 4, y: (LAYERS.length - 1) * spread * 0.34, ease: "none" },
        0
      );

      plates.forEach((plate, i) => {
        // Top plate travels furthest: the environment peels apart from the
        // outside in, which is the order an intrusion actually reaches it.
        const lift = (LAYERS.length - 1 - i) * spread;
        timeline.fromTo(
          plate,
          { z: 0 },
          { z: lift, ease: "none" },
          0
        );
        // Each label lands as its own plate clears the one beneath it.
        timeline.to(
          cards[i],
          { opacity: 1, x: 0, duration: 0.16, ease: "power2.out" },
          i * 0.14
        );
      });
    }, sectionRef);

    return () => context.revert();
  }, [reduced]);

  const activeIndex = Math.min(
    LAYERS.length - 1,
    Math.floor(progress * LAYERS.length)
  );

  return (
    <section ref={sectionRef} className="relative z-10 h-[380vh]">
      <div className="sticky top-0 flex h-dvh flex-col overflow-hidden">
        <div className="mx-auto w-full max-w-[96rem] px-6 pt-12 sm:px-10">
          <p className="font-mono text-xs uppercase tracking-[0.3em] text-cyan">
            Anatomy of an intrusion
          </p>
          <h2 className="mt-3 max-w-xl font-display text-2xl font-semibold text-white sm:text-3xl">
            Scroll to take the environment apart.
          </h2>
          <p className="mt-2 max-w-md font-mono text-sm text-text-mid">
            Every layer an attacker crosses, and the ATT&CK tactic that gets them through it.
          </p>
        </div>

        <div className="relative flex flex-1 items-center justify-center">
          {/* Exploded stack */}
          <div
            className="relative flex items-center justify-center"
            style={{ perspective: "1300px", perspectiveOrigin: "50% 45%" }}
          >
            <div
              ref={stackRef}
              className="relative"
              style={{
                transformStyle: "preserve-3d",
                // Scales with the viewport so the plates never outgrow a narrow
                // window (where they used to overlap the heading).
                width: "min(340px, 62vw)",
                height: "min(210px, 38vw)",
              }}
            >
              {LAYERS.map((layer, i) => (
                <div
                  key={layer.tacticId}
                  ref={(el) => {
                    plateRefs.current[i] = el;
                  }}
                  className="absolute inset-0 rounded-2xl border"
                  style={{
                    transformStyle: "preserve-3d",
                    // Liquid glass WITHOUT backdrop-filter. These six plates
                    // rotate together inside a preserve-3d context, and a
                    // blurred backdrop there forces the compositor to
                    // re-rasterize all six every frame. The layered gradient
                    // plus the bright top edge below reproduces the glass read
                    // at effectively zero per-frame cost.
                    background:
                      "linear-gradient(135deg, rgba(0,245,255,0.16) 0%, rgba(180,220,255,0.07) 42%, rgba(124,58,237,0.14) 100%)",
                    borderColor: "rgba(0,245,255,0.28)",
                    boxShadow:
                      "inset 0 1px 0 rgba(255,255,255,0.22), inset 0 -1px 0 rgba(0,245,255,0.10), 0 26px 70px -28px rgba(0,245,255,0.45)",
                  }}
                >
                  <div className="flex h-full flex-col justify-between p-4">
                    <span className="font-mono text-[10px] uppercase tracking-[0.24em] text-cyan/80">
                      {layer.tacticId}
                    </span>
                    <span className="font-display text-sm font-semibold text-white/90">
                      {layer.label}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Labels reveal as their plate separates */}
          <div className="pointer-events-none absolute inset-y-0 right-6 hidden w-[300px] flex-col justify-center gap-3 sm:right-10 lg:flex">
            {LAYERS.map((layer, i) => (
              <div
                key={layer.tacticId}
                ref={(el) => {
                  cardRefs.current[i] = el;
                }}
                className="rounded-xl border px-3.5 py-2.5"
                style={{
                  background:
                    i === activeIndex
                      ? "linear-gradient(135deg, rgba(0,245,255,0.14), rgba(255,255,255,0.03))"
                      : "rgba(13,14,23,0.55)",
                  backdropFilter: "blur(10px)",
                  WebkitBackdropFilter: "blur(10px)",
                  borderColor:
                    i === activeIndex ? "rgba(0,245,255,0.45)" : "rgba(31,58,68,0.8)",
                }}
              >
                <p className="font-mono text-[10px] uppercase tracking-[0.2em] text-cyan/80">
                  {layer.tacticId} · {layer.tactic}
                </p>
                <p className="mt-1 font-display text-sm font-semibold text-white">
                  {layer.label}
                </p>
                <p className="mt-0.5 font-mono text-[11px] leading-snug text-text-mid">
                  {layer.detail}
                </p>
              </div>
            ))}
          </div>
        </div>

        {/* Scrub position - the same affordance a scrubbed video gives. */}
        <div className="mx-auto w-full max-w-[96rem] px-6 pb-10 sm:px-10">
          <div className="flex items-center gap-3 font-mono text-[10px] uppercase tracking-[0.24em] text-text-dim">
            <span className="tabular-nums">{String(activeIndex + 1).padStart(2, "0")}</span>
            <span className="relative h-px flex-1 bg-border-dim">
              <span
                className="absolute inset-y-0 left-0 bg-cyan"
                style={{ width: `${Math.round(progress * 100)}%` }}
              />
            </span>
            <span className="tabular-nums">{String(LAYERS.length).padStart(2, "0")}</span>
          </div>
        </div>
      </div>
    </section>
  );
}
