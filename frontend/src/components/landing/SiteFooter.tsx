import { Link } from "react-router-dom";
import { motion, useReducedMotion } from "framer-motion";
import { ArrowRight, ArrowSquareOut, Circle } from "@phosphor-icons/react";

/**
 * Landing footer.
 *
 * Motion here is deliberately quieter than the sections above it. A footer is
 * the end of a scroll, not another act: it resolves once, on arrival, and then
 * holds still. Everything animates on `whileInView` with `once: true`, so
 * scrolling back up does not replay it.
 */

const LINKS = [
  { label: "MITRE ATT&CK®", href: "https://attack.mitre.org", external: true },
  { label: "ATT&CK Groups", href: "https://attack.mitre.org/groups/", external: true },
  { label: "ATT&CK Techniques", href: "https://attack.mitre.org/techniques/enterprise/", external: true },
];

const FACTS = [
  { value: "4,368", label: "Entities" },
  { value: "15", label: "Edge types" },
  { value: "0", label: "Unverified IDs" },
];

export function SiteFooter() {
  const reduced = useReducedMotion();
  const rise = reduced
    ? {}
    : {
        initial: { opacity: 0, y: 14 },
        whileInView: { opacity: 1, y: 0 },
        viewport: { once: true, amount: 0.3 },
      };

  return (
    <footer className="relative z-10 mt-24 overflow-hidden">
      {/* Horizon: a light source sitting just under the top edge, so the footer
          reads as the page settling onto a surface rather than a boxed-off
          block. Drawn outward from the centre as it enters view. */}
      <motion.div
        aria-hidden="true"
        className="mx-auto h-px w-full max-w-[96rem] origin-center"
        style={{
          background:
            "linear-gradient(90deg, transparent, rgba(0,245,255,0.55) 35%, rgba(124,58,237,0.5) 65%, transparent)",
        }}
        initial={reduced ? undefined : { scaleX: 0, opacity: 0 }}
        whileInView={reduced ? undefined : { scaleX: 1, opacity: 1 }}
        viewport={{ once: true, amount: 0.6 }}
        transition={{ duration: 1.1, ease: [0.16, 1, 0.3, 1] }}
      />
      <div
        aria-hidden="true"
        className="pointer-events-none absolute inset-x-0 top-0 h-40"
        style={{
          background:
            "radial-gradient(ellipse 55% 100% at 50% 0%, rgba(0,245,255,0.10), transparent 70%)",
        }}
      />

      <div className="mx-auto grid w-full max-w-[96rem] gap-10 px-6 py-14 sm:px-10 lg:grid-cols-[1.4fr_1fr_1fr]">
        <motion.div {...rise} transition={{ duration: 0.5, ease: "easeOut" }}>
          <p className="font-display text-lg font-semibold tracking-tight text-white">
            THREAT<span className="text-cyan">INTEL</span>.AI
          </p>
          <p className="mt-3 max-w-sm text-sm leading-relaxed text-text-mid">
            Answers traced through a real ATT&amp;CK knowledge graph — every identifier
            checked back against the graph before it reaches you.
          </p>

          <div className="mt-6 flex flex-wrap gap-x-7 gap-y-3">
            {FACTS.map((fact, index) => (
              <motion.div
                key={fact.label}
                {...rise}
                transition={{ duration: 0.45, delay: 0.12 + index * 0.08, ease: "easeOut" }}
              >
                <p className="font-display text-xl font-semibold text-white tabular-nums">
                  {fact.value}
                </p>
                <p className="font-mono text-[10px] uppercase tracking-[0.2em] text-text-dim">
                  {fact.label}
                </p>
              </motion.div>
            ))}
          </div>
        </motion.div>

        <motion.nav
          {...rise}
          transition={{ duration: 0.5, delay: 0.08, ease: "easeOut" }}
          aria-label="Reference"
        >
          <p className="font-mono text-[10px] uppercase tracking-[0.25em] text-text-dim">
            Reference
          </p>
          <ul className="mt-4 space-y-2.5">
            {LINKS.map((link) => (
              <li key={link.label}>
                <a
                  href={link.href}
                  target={link.external ? "_blank" : undefined}
                  rel={link.external ? "noreferrer" : undefined}
                  className="group/link inline-flex items-center gap-1.5 text-sm text-text-mid transition-colors hover:text-cyan"
                >
                  {link.label}
                  <ArrowSquareOut
                    size={12}
                    weight="bold"
                    aria-hidden="true"
                    className="opacity-0 transition-all duration-200 group-hover/link:-translate-y-px group-hover/link:translate-x-px group-hover/link:opacity-100"
                  />
                </a>
              </li>
            ))}
          </ul>
        </motion.nav>

        <motion.div {...rise} transition={{ duration: 0.5, delay: 0.16, ease: "easeOut" }}>
          <p className="font-mono text-[10px] uppercase tracking-[0.25em] text-text-dim">
            Console
          </p>
          <Link
            to="/chat"
            className="group/cta mt-4 inline-flex items-center gap-2 rounded-lg border border-cyan/30 px-4 py-2.5 font-mono text-xs uppercase tracking-wider text-cyan transition-colors hover:border-cyan/60"
            style={{
              background:
                "linear-gradient(140deg, rgba(0,245,255,0.10) 0%, rgba(13,14,23,0.7) 60%)",
              boxShadow: "inset 0 1px 0 rgba(255,255,255,0.10)",
            }}
          >
            Query the graph
            <ArrowRight
              size={13}
              weight="bold"
              aria-hidden="true"
              className="transition-transform duration-200 group-hover/cta:translate-x-0.5"
            />
          </Link>

          <p className="mt-5 flex items-center gap-1.5 font-mono text-[11px] text-text-dim">
            <motion.span
              aria-hidden="true"
              className="flex text-green"
              // Slow breath, not a blink: a status light that is alive but not
              // demanding attention at the very bottom of the page.
              animate={reduced ? undefined : { opacity: [0.45, 1, 0.45] }}
              transition={{ duration: 2.8, repeat: Infinity, ease: "easeInOut" }}
            >
              <Circle size={7} weight="fill" />
            </motion.span>
            Graph RAG · grounded retrieval
          </p>
        </motion.div>
      </div>

      <div className="mx-auto w-full max-w-[96rem] border-t border-border-dim px-6 py-5 sm:px-10">
        <p className="text-center font-mono text-[10px] uppercase tracking-[0.18em] text-text-dim">
          MITRE ATT&amp;CK® is a registered trademark of The MITRE Corporation · Data for research purposes
        </p>
      </div>
    </footer>
  );
}
