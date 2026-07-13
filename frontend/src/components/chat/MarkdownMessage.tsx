import { useMemo, type ReactNode } from "react";
import { clsx } from "clsx";
import ReactMarkdown, { type Components } from "react-markdown";
import remarkGfm from "remark-gfm";
import { rehypeMitreHighlight } from "../../lib/rehypeMitreHighlight";
import { rehypeAnswerSections } from "../../lib/rehypeAnswerSections";
import { categoryMetaFor, sectionId } from "../../lib/answerSections";
import { ACCENT_CLASSES } from "../../lib/colorTokens";
import { MitreId } from "./MitreId";

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
  a: ({ children, href }) => (
    <a
      href={href}
      target="_blank"
      rel="noreferrer"
      className="text-cyan underline decoration-cyan/30 underline-offset-2 hover:decoration-cyan"
    >
      {children}
    </a>
  ),
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

export function MarkdownMessage({ text, messageId }: { text: string; messageId: string }) {
  const components = useMemo<Components>(
    () => ({
      ...baseComponents,
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
    [messageId]
  );

  return (
    <div className="text-sm leading-relaxed text-[#e6f6f8]">
      <ReactMarkdown
        remarkPlugins={[remarkGfm]}
        rehypePlugins={[rehypeAnswerSections, rehypeMitreHighlight]}
        components={components}
      >
        {text}
      </ReactMarkdown>
    </div>
  );
}
