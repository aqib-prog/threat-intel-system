import { useLayoutEffect, useRef } from "react";
import gsap from "gsap";
import { ScrollTrigger } from "gsap/ScrollTrigger";
import { useReducedMotion } from "../../hooks/useReducedMotion";

gsap.registerPlugin(ScrollTrigger);

/**
 * "How an answer is built" - the retrieval pipeline as a vertical run of glass
 * stages, revealed on scroll with a connector that draws between them.
 *
 * Deliberately a flowing reveal rather than another pinned scrub: the section
 * above already holds the reader in place, and two pinned sequences back to
 * back makes a page feel like it is fighting the scroll. The connector drawing
 * downward is the motion carrying the meaning - it is the query descending
 * through the stages.
 */

interface Stage {
  index: string;
  title: string;
  body: string;
  metric: string;
}

// These are the real stages in orchestration/pipeline.py, in execution order.
const STAGES: Stage[] = [
  {
    index: "01",
    title: "Guardrail",
    body: "Off-topic and harmful requests stop here, before anything is retrieved. Benign lookups skip the classifier entirely so they answer fast.",
    metric: "3 layers",
  },
  {
    index: "02",
    title: "Entity resolution",
    body: "Names, aliases, and MITRE IDs are matched against the graph. Typos resolve; a code that does not exist is refused instead of guessed at.",
    metric: "4,368 entities",
  },
  {
    index: "03",
    title: "Graph traversal",
    body: "Answers follow real ATT&CK relationships out of Neo4j — attributed-to, uses, mitigates — rather than whatever text looked similar.",
    metric: "15 edge types",
  },
  {
    index: "04",
    title: "Rerank",
    body: "Candidates are scored against the question and weak context is dropped, so the model reads a short, relevant set instead of everything.",
    metric: "cross-encoder",
  },
  {
    index: "05",
    title: "Grounded answer",
    body: "Every identifier in the response is checked back against the graph. Anything unverified never renders as a citation.",
    metric: "0 unverified IDs",
  },
];

export function PipelineFlow() {
  const sectionRef = useRef<HTMLElement>(null);
  const lineRef = useRef<HTMLSpanElement>(null);
  const rowRefs = useRef<(HTMLDivElement | null)[]>([]);
  const reduced = useReducedMotion();

  useLayoutEffect(() => {
    const context = gsap.context(() => {
      const rows = rowRefs.current.filter(Boolean) as HTMLDivElement[];
      if (!rows.length) return;

      if (reduced) {
        gsap.set(rows, { opacity: 1, y: 0, rotateX: 0 });
        gsap.set(lineRef.current, { scaleY: 1 });
        return;
      }

      // The connector draws as the section passes, tying the stages together
      // into one descending path rather than five separate cards.
      gsap.fromTo(
        lineRef.current,
        { scaleY: 0 },
        {
          scaleY: 1,
          ease: "none",
          scrollTrigger: {
            trigger: sectionRef.current,
            start: "top 65%",
            end: "bottom 75%",
            scrub: 0.5,
          },
        }
      );

      rows.forEach((row) => {
        gsap.fromTo(
          row,
          { opacity: 0, y: 34, rotateX: -12 },
          {
            opacity: 1,
            y: 0,
            rotateX: 0,
            duration: 0.7,
            ease: "power3.out",
            scrollTrigger: { trigger: row, start: "top 82%", once: true },
          }
        );
      });
    }, sectionRef);

    return () => context.revert();
  }, [reduced]);

  return (
    <section ref={sectionRef} className="relative z-10 mx-auto max-w-[96rem] px-6 py-28 sm:px-10">
      <p className="font-mono text-xs uppercase tracking-[0.3em] text-cyan">
        How an answer is built
      </p>
      <h2 className="mt-3 max-w-2xl font-display text-2xl font-semibold text-white sm:text-3xl">
        Five stages between your question and a citation.
      </h2>

      <div className="relative mt-14 pl-8 sm:pl-12" style={{ perspective: "1000px" }}>
        {/* Connector rail */}
        <span
          aria-hidden="true"
          className="absolute left-[7px] top-2 h-[calc(100%-2rem)] w-px bg-border-dim sm:left-[15px]"
        />
        <span
          ref={lineRef}
          aria-hidden="true"
          className="absolute left-[7px] top-2 h-[calc(100%-2rem)] w-px origin-top bg-gradient-to-b from-cyan via-cyan/70 to-purple sm:left-[15px]"
          style={{ boxShadow: "0 0 12px rgba(0,245,255,0.55)" }}
        />

        <div className="flex flex-col gap-5">
          {STAGES.map((stage, i) => (
            <div
              key={stage.index}
              ref={(el) => {
                rowRefs.current[i] = el;
              }}
              className="group relative rounded-2xl border px-5 py-5 transition-colors duration-300 sm:px-6"
              style={{
                transformStyle: "preserve-3d",
                background:
                  "linear-gradient(135deg, rgba(0,245,255,0.07) 0%, rgba(255,255,255,0.022) 45%, rgba(124,58,237,0.06) 100%)",
                backdropFilter: "blur(12px) saturate(140%)",
                WebkitBackdropFilter: "blur(12px) saturate(140%)",
                borderColor: "rgba(31,58,68,0.9)",
                boxShadow: "inset 0 1px 0 rgba(255,255,255,0.14)",
              }}
            >
              {/* Node on the rail */}
              <span
                aria-hidden="true"
                className="absolute -left-8 top-7 h-2.5 w-2.5 rounded-full border border-cyan/60 bg-void sm:-left-12"
                style={{ boxShadow: "0 0 10px rgba(0,245,255,0.7)" }}
              />
              <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
                <span className="font-mono text-[11px] tracking-[0.2em] text-cyan/70">
                  {stage.index}
                </span>
                <h3 className="font-display text-lg font-semibold text-white">{stage.title}</h3>
                <span className="ml-auto rounded-full border border-cyan/25 bg-cyan/10 px-2.5 py-0.5 font-mono text-[10px] uppercase tracking-wider text-cyan">
                  {stage.metric}
                </span>
              </div>
              <p className="mt-2 max-w-2xl font-mono text-[13px] leading-relaxed text-text-mid">
                {stage.body}
              </p>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}
