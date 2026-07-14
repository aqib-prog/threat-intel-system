import type { Root, RootContent, Element } from "hast";
import { canonicalSectionLabel } from "./answerSections";

function isElement(node: RootContent | Element["children"][number] | null | undefined): node is Element {
  return Boolean(node && node.type === "element");
}

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
    if (!/^[A-Za-z][A-Za-z /-]{1,80}:\s*$/.test(fullText)) return null;
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
    tree.children = groupSections(expandInlineExplanationSections(tree.children)) as Root["children"];
  };
}

function meaningfulChildIndex(children: Element["children"]): number {
  return children.findIndex((child) => {
    if (child.type === "text") return child.value.trim().length > 0;
    return true;
  });
}

function stripLeadingColon(children: Element["children"]): Element["children"] {
  const [first, ...rest] = children;
  if (first?.type !== "text") return children;

  const value = first.value.replace(/^\s*:\s*/, "");
  if (!value) return rest;
  return [{ ...first, value }, ...rest];
}

function inlineExplanationCardFromListItem(node: RootContent): Element | null {
  if (!isElement(node) || node.tagName !== "li") return null;

  const firstMeaningful = meaningfulChildIndex(node.children);
  if (firstMeaningful < 0) return null;

  const first = node.children[firstMeaningful];
  const contentContainer =
    isElement(first) && first.tagName === "p"
      ? first
      : ({ ...node, children: node.children.slice(firstMeaningful) } as Element);

  const contentStart = meaningfulChildIndex(contentContainer.children);
  const lead = contentStart >= 0 ? contentContainer.children[contentStart] : null;

  if (isElement(lead) && lead.tagName === "strong") {
    const label = canonicalSectionLabel(textOf(lead).replace(/:$/, "").trim());
    if (!label) return null;

    const rest = stripLeadingColon(contentContainer.children.slice(contentStart + 1));
    if (!rest.some((child) => textOf(child as RootContent).trim().length > 0)) return null;

    return {
      type: "element",
      tagName: "answer-section",
      properties: { label, variant: "inline" },
      children: [{ type: "element", tagName: "p", properties: {}, children: rest }],
    };
  }

  if (lead?.type === "text") {
    const match = lead.value.match(/^\s*([A-Za-z][A-Za-z /-]{1,60}):\s*(.*)$/);
    if (!match) return null;

    const label = canonicalSectionLabel(match[1]);
    if (!label) return null;

    const replacement = match[2]
      ? [{ ...lead, value: match[2] }, ...contentContainer.children.slice(contentStart + 1)]
      : contentContainer.children.slice(contentStart + 1);
    if (!replacement.some((child) => textOf(child as RootContent).trim().length > 0)) return null;

    return {
      type: "element",
      tagName: "answer-section",
      properties: { label, variant: "inline" },
      children: [{ type: "element", tagName: "p", properties: {}, children: replacement }],
    };
  }

  return null;
}

function cloneWithChildren(node: Element, children: Element["children"]): Element {
  return { ...node, children };
}

// Matches a list item whose entire content is a bare "Label:" with nothing
// after the colon (e.g. the LLM enumerates tactic/technique names one per
// line instead of the more common single comma-joined line) - there's no
// value coming, so the trailing colon is a dangling artifact, not a label
// for content that follows.
const DANGLING_LABEL_RE = /^[A-Za-z][A-Za-z0-9 /-]{0,60}:$/;

function stripTrailingColon(children: Element["children"]): Element["children"] {
  for (let i = children.length - 1; i >= 0; i--) {
    const child = children[i];
    if (child.type === "text" && child.value.trim()) {
      const trimmedEnd = child.value.replace(/:(\s*)$/, "$1");
      return [...children.slice(0, i), { ...child, value: trimmedEnd }, ...children.slice(i + 1)];
    }
    if (isElement(child)) {
      const newChildren = stripTrailingColon(child.children as Element["children"]);
      if (newChildren !== child.children) {
        return [...children.slice(0, i), { ...child, children: newChildren }, ...children.slice(i + 1)];
      }
    }
  }
  return children;
}

function stripDanglingLabelColon(node: RootContent): RootContent {
  if (!isElement(node)) return node;
  const text = textOf(node).trim();
  if (!DANGLING_LABEL_RE.test(text)) return node;
  return cloneWithChildren(node, stripTrailingColon(node.children));
}

function expandInlineExplanationSections(nodes: RootContent[]): RootContent[] {
  const result: RootContent[] = [];

  for (const node of nodes) {
    if (!isElement(node)) {
      result.push(node);
      continue;
    }

    if (node.tagName === "ul" || node.tagName === "ol") {
      const expanded: RootContent[] = [];
      let pendingListItems: Element["children"] = [];

      const flushPendingList = () => {
        if (!pendingListItems.length) return;
        expanded.push(cloneWithChildren(node, pendingListItems));
        pendingListItems = [];
      };

      for (const child of node.children) {
        const card = inlineExplanationCardFromListItem(child as RootContent);
        if (card) {
          flushPendingList();
          expanded.push(card);
          continue;
        }

        pendingListItems.push(
          isElement(child)
            ? stripDanglingLabelColon(
                cloneWithChildren(child, expandInlineExplanationSections(child.children as RootContent[]) as Element["children"])
              ) as Element
            : child
        );
      }

      flushPendingList();
      result.push(...expanded);
      continue;
    }

    result.push(cloneWithChildren(node, expandInlineExplanationSections(node.children as RootContent[]) as Element["children"]));
  }

  return result;
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
