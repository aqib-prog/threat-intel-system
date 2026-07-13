import type { Root, RootContent, Element } from "hast";
import { canonicalSectionLabel } from "./answerSections";

function textOf(node: RootContent): string {
  if (node.type === "text") return node.value;
  if ("children" in node) return (node.children as RootContent[]).map(textOf).join("");
  return "";
}

function sectionLabel(node: RootContent): { label: string; heading: string } | null {
  if (node.type !== "element" || node.tagName !== "p") return null;
  const first = node.children[0];

  let heading = "";
  if (first?.type === "element" && first.tagName === "strong") {
    heading = textOf(first).replace(/:$/, "").trim();
  } else {
    const fullText = textOf(node).trim();
    if (!/^[A-Za-z][A-Za-z ]{2,80}:\s*$/.test(fullText)) return null;
    heading = fullText.replace(/:$/, "").trim();
  }

  const label = canonicalSectionLabel(heading);
  return label ? { label, heading } : null;
}

/**
 * Groups everything from a recognized bold label (e.g. "**Tactics:**") up to
 * the next recognized label into one <answer-section> container - the
 * paragraph tail plus any following lists/blockquotes - so MarkdownMessage
 * can render each category as its own bordered card instead of a bare
 * inline bold prefix.
 */
export function rehypeAnswerSections() {
  return (tree: Root) => {
    tree.children = groupSections(tree.children) as Root["children"];
  };
}

function groupSections(nodes: RootContent[]): RootContent[] {
  const result: RootContent[] = [];
  let current: { label: string; children: RootContent[] } | null = null;

  const flush = () => {
    if (!current) return;
    const section: Element = {
      type: "element",
      tagName: "answer-section",
      properties: { label: current.label },
      children: current.children as Element["children"],
    };
    result.push(section);
    current = null;
  };

  for (const node of nodes) {
    const section = sectionLabel(node);
    if (section) {
      flush();
      const first = (node as Element).children[0];
      const rest =
        first?.type === "element" && first.tagName === "strong"
          ? (node as Element).children.slice(1)
          : [];
      const hasTail = rest.some((n) => textOf(n).trim().length > 0);
      const headingElement: Element | null =
        section.heading !== section.label
          ? {
              type: "element",
              tagName: "p",
              properties: { className: ["answer-section-heading"] },
              children: [{ type: "text", value: section.heading }],
            }
          : null;
      current = {
        label: section.label,
        children: [
          ...(headingElement ? [headingElement] : []),
          ...(hasTail ? [{ type: "element", tagName: "p", properties: {}, children: rest } as Element] : []),
        ],
      };
    } else if (current) {
      current.children.push(node);
    } else {
      result.push(node);
    }
  }
  flush();

  return result;
}
