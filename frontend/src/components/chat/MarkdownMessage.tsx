import { useMemo, type ReactNode } from "react";
import { clsx } from "clsx";
import ReactMarkdown, { type Components, type Options } from "react-markdown";
import remarkGfm from "remark-gfm";
import { rehypeMitreHighlight } from "../../lib/rehypeMitreHighlight";
import { rehypeAnswerSections } from "../../lib/rehypeAnswerSections";
import { canonicalSectionLabel, categoryMetaFor, sectionId } from "../../lib/answerSections";
import { extractMitreId, extractMitreIds, mitreCitationUrl } from "../../lib/mitre";
import { ACCENT_CLASSES } from "../../lib/colorTokens";
import type { NodeSource } from "../../lib/types";
import { MitreId } from "./MitreId";

// Renders a markdown link as its plain name + a compact "cite ↗" chip, but
// only when the link resolves to a real MITRE page AND (when a grounded id set
// is known) the cited id actually exists in our graph. Everything else - dead
// pages, non-MITRE urls, hallucinated/ungrounded ids - renders as plain text
// with no citation, so a user never sees a wrong or non-working source.
const EMPTY_NODE_URLS = new Map<string, string>();

function makeCitationLink(
  grounded: Set<string> | null,
  nodeUrls: ReadonlyMap<string, string>,
) {
  return function CitationLink({ children, href }: { children?: ReactNode; href?: string }) {
    const hrefIds = extractMitreIds(href);
    const childId = typeof children === "string" ? extractMitreId(children) : null;
    // Analytic URLs contain both the parent DET#### and the #AN#### fragment.
    // Prefer a visible mapped ID, then the most-specific/rightmost mapped ID,
    // before falling back to the original first-ID reconstruction behavior.
    const authoritativeId = childId && nodeUrls.has(childId)
      ? childId
      : [...hrefIds].reverse().find((candidate) => nodeUrls.has(candidate));
    const id = authoritativeId ?? hrefIds[0];
    if (!id) return <>{children}</>;
    if (grounded) {
      if (!grounded.has(id)) return <>{children}</>;
    }
    const cite = authoritativeId ? nodeUrls.get(authoritativeId) : mitreCitationUrl(href);
    if (!cite) return <>{children}</>;
    return (
      <>
        {children}
        <a
          href={cite}
          target="_blank"
          rel="noreferrer"
          className="ml-0.5 whitespace-nowrap rounded border border-amber/25 bg-amber/10 px-1 py-px align-baseline font-mono text-[10px] font-semibold text-amber no-underline hover:border-amber/50 hover:bg-amber/20"
        >
          cite ↗
        </a>
      </>
    );
  };
}

const baseComponents: Components = {
  p: ({ children, className }) => (
    <p
      className={clsx(
        "mb-3 whitespace-pre-wrap last:mb-0",
        className === "answer-section-heading" &&
          "font-display text-sm font-semibold text-white"
      )}
    >
      {children}
    </p>
  ),
  strong: ({ children }) => <strong className="font-semibold text-white">{children}</strong>,
  em: ({ children }) => <em className="text-[#d4e8ea] italic">{children}</em>,
  ul: ({ children }) => <ul className="mb-3 ml-4 list-disc space-y-1 marker:text-cyan/60 last:mb-0">{children}</ul>,
  ol: ({ children }) => <ol className="mb-3 ml-4 list-decimal space-y-1 marker:text-cyan/60 last:mb-0">{children}</ol>,
  li: ({ children }) => <li className="pl-1">{children}</li>,
  // Default (ungrounded) link renderer; MarkdownMessage overrides this with a
  // grounded variant once it knows which ids exist in the graph.
  a: makeCitationLink(null, EMPTY_NODE_URLS),
  code: ({ children }) => (
    <code className="rounded border border-border-glow bg-void-raised px-1 py-0.5 font-mono text-[0.85em] text-green">
      {children}
    </code>
  ),
  pre: ({ children }) => (
    <pre className="mb-3 overflow-x-auto rounded-lg border border-border-glow bg-void-raised p-3 font-mono text-xs last:mb-0">
      {children}
    </pre>
  ),
  blockquote: ({ children }) => (
    <blockquote className="mb-3 border-l-2 border-cyan/30 pl-3 text-text-mid last:mb-0">{children}</blockquote>
  ),
  h1: ({ children }) => <h1 className="mb-2 font-display text-base font-semibold text-white">{children}</h1>,
  h2: ({ children }) => <h2 className="mb-2 font-display text-base font-semibold text-white">{children}</h2>,
  h3: ({ children }) => <h3 className="mb-2 font-display text-sm font-semibold text-white">{children}</h3>,
  hr: () => <hr className="my-3 border-border-dim" />,
  table: ({ children }) => (
    <div className="mb-3 overflow-x-auto last:mb-0">
      <table className="w-full border-collapse text-left text-xs">{children}</table>
    </div>
  ),
  thead: ({ children }) => <thead className="border-b border-border-glow text-text-mid">{children}</thead>,
  th: ({ children }) => <th className="px-2 py-1.5 font-mono uppercase tracking-wider">{children}</th>,
  td: ({ children }) => <td className="border-t border-border-dim px-2 py-1.5">{children}</td>,
  // @ts-expect-error -- custom hast tag injected by rehypeMitreHighlight, not a standard HTML element
  "mitre-id": ({ id }: { id: string }) => <MitreId id={id} />,
};

const PLAIN_LABEL_LINE_RE = /^(\s*)([A-Za-z][A-Za-z /-]{1,60}):\s+(.+)$/;
// A standalone line that is just "Name:" with nothing after it - e.g. the
// LLM enumerates items one per line instead of a single comma-joined line.
// Recognized category headings (canonicalSectionLabel matches) are left
// alone since their trailing colon is meaningful there; anything else has
// no value coming and the colon is a dangling artifact.
const BARE_LABEL_LINE_RE = /^(\s*)([A-Za-z][A-Za-z /-]{1,60}):\s*$/;
// A short, title-case-ish label ("Log Sources", "Detection Strategy") looks
// like a real backend field name a maintainer forgot to register in
// answerSections.ts's CATEGORY_META/CANONICAL_LABELS - as opposed to
// ordinary prose that happens to contain a colon ("note:", "for example:").
// Anything all-lowercase or a single common word is assumed to be prose, not
// a field name, and skipped to avoid warning on every sentence.
const LOOKS_LIKE_FIELD_LABEL_RE = /^(?:[A-Z][a-z]*)(?:\s+[A-Za-z]+){0,4}$/;
const knownUnregisteredLabels = new Set<string>();

function warnIfLooksLikeMissingLabel(rawLabel: string): void {
  if (!import.meta.env.DEV) return;
  const trimmed = rawLabel.trim();
  if (!LOOKS_LIKE_FIELD_LABEL_RE.test(trimmed)) return;
  if (knownUnregisteredLabels.has(trimmed)) return;
  knownUnregisteredLabels.add(trimmed);
  // eslint-disable-next-line no-console
  console.warn(
    `[MarkdownMessage] "${trimmed}:" looks like a backend field label but isn't ` +
      `registered in answerSections.ts (CATEGORY_META/CANONICAL_LABELS). It will ` +
      `render as plain text instead of a styled section card. If this is a real ` +
      `field, add it there - this is the same bug class as the missing ` +
      `"Log Sources" label.`
  );
}

// The backend truncates long descriptions mid-string, and the typewriter
// reveals markdown one character at a time - both leave a dangling "[label" or
// "[label](partial-url" at the very end that ReactMarkdown renders as literal
// noise (e.g. a stray "[AP"). Anchored to end-of-string so complete links
// earlier in the text are untouched.
function stripTrailingIncompleteLink(text: string): string {
  return text
    .replace(/\[[^\]]*\]\([^)]*$/, "")
    .replace(/\[[^\]]*$/, "")
    .replace(/[ \t]+$/, "");
}

function normalizePlainLabeledLines(text: string): string {
  const output: string[] = [];
  let inFence = false;

  for (const line of text.split(/\r?\n/)) {
    if (/^\s*```/.test(line)) {
      inFence = !inFence;
      output.push(line);
      continue;
    }

    if (inFence || /^\s*(?:[-*]|\d+\.)\s+/.test(line)) {
      output.push(line);
      continue;
    }

    const match = line.match(PLAIN_LABEL_LINE_RE);
    const label = match ? canonicalSectionLabel(match[2]) : null;
    if (match && !label) warnIfLooksLikeMissingLabel(match[2]);
    if (match && label) {
      const previous = output[output.length - 1];
      if (previous && previous.trim()) output.push("");
      output.push(`${match[1]}**${label}:** ${match[3].trim()}`);
      output.push("");
      continue;
    }

    const bareMatch = line.match(BARE_LABEL_LINE_RE);
    const bareLabel = bareMatch ? canonicalSectionLabel(bareMatch[2]) : null;
    if (bareMatch && bareLabel) {
      // Recognized bare label with its value on following lines (e.g.
      // "Analytics:\n- foo\n- bar") needs the same bold + blank-line
      // isolation as the inline case above, so it becomes its own paragraph
      // instead of merging into whatever plain-text line precedes it -
      // rehypeAnswerSections only recognizes a bare "Label:" as a section
      // boundary when it is the paragraph's *entire* text.
      const previous = output[output.length - 1];
      if (previous && previous.trim()) output.push("");
      output.push(`${bareMatch[1]}**${bareLabel}:**`);
      output.push("");
      continue;
    }
    if (bareMatch) {
      warnIfLooksLikeMissingLabel(bareMatch[2]);
      output.push(`${bareMatch[1]}${bareMatch[2]}`);
      continue;
    }
    output.push(line);
  }

  return output.join("\n").replace(/\n{3,}/g, "\n\n");
}

export function MarkdownMessage({
  text,
  messageId,
  groundedIds,
  nodes,
}: {
  text: string;
  messageId: string;
  groundedIds?: string[];
  nodes?: NodeSource[];
}) {
  const normalizedText = useMemo(
    () => normalizePlainLabeledLines(stripTrailingIncompleteLink(text)),
    [text]
  );
  // A set when the backend told us which ids exist in the graph (even if
  // empty); null when it did not (mock/offline) so we degrade to showing all.
  const groundedSet = useMemo(
    () => (groundedIds ? new Set(groundedIds.map((id) => id.toUpperCase())) : null),
    [groundedIds]
  );
  const nodeUrls = useMemo(() => {
    const urls = new Map<string, string>();
    for (const node of nodes ?? []) {
      if (node.external_id && node.url) {
        urls.set(node.external_id.toUpperCase(), node.url);
      }
    }
    return urls;
  }, [nodes]);
  const rehypePlugins = useMemo<NonNullable<Options["rehypePlugins"]>>(
    () => [rehypeAnswerSections, [rehypeMitreHighlight, groundedSet ?? undefined]],
    [groundedSet]
  );
  const components = useMemo<Components>(
    () => ({
      ...baseComponents,
      a: makeCitationLink(groundedSet, nodeUrls),
      "mitre-id": ({ id }: { id: string }) => (
        <MitreId id={id} authoritativeUrl={nodeUrls.get(id.toUpperCase())} />
      ),
      "answer-section": ({ label, children }: { label: string; children?: ReactNode }) => {
        const meta = categoryMetaFor(label);
        if (!meta) return null;
        const Icon = meta.icon;
        const accent = ACCENT_CLASSES[meta.accent];
        return (
          <div
            id={sectionId(messageId, label)}
            className={clsx(
              "scroll-mt-4 mb-3 overflow-hidden rounded-lg border bg-void-panel/50 transition-shadow last:mb-0",
              accent.border
            )}
          >
            <div className={clsx("flex items-center gap-2 border-b px-3 py-2", accent.border, accent.bg)}>
              <span className={clsx("flex h-5 w-5 shrink-0 items-center justify-center rounded", accent.bg)}>
                <Icon size={12} weight="bold" className={accent.text} aria-hidden="true" />
              </span>
              <span className={clsx("font-mono text-[11px] font-semibold uppercase tracking-wider", accent.text)}>
                {label}
              </span>
            </div>
            <div className="px-3 py-2.5">{children}</div>
          </div>
        );
      },
    }),
    [messageId, groundedSet, nodeUrls]
  );

  return (
    <div className="text-sm leading-relaxed text-[#e6f6f8]">
      <ReactMarkdown
        remarkPlugins={[remarkGfm]}
        rehypePlugins={rehypePlugins}
        components={components}
      >
        {normalizedText}
      </ReactMarkdown>
    </div>
  );
}
