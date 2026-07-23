import type { Root, RootContent, Element } from "hast";
import { MITRE_ID_PATTERN } from "./mitre";

function highlightChildren(
  children: RootContent[],
  insideLink: boolean,
  grounded: Set<string> | undefined,
): RootContent[] {
  const result: RootContent[] = [];

  for (const node of children) {
    if (node.type === "text" && !insideLink) {
      MITRE_ID_PATTERN.lastIndex = 0;
      const parts = node.value.split(MITRE_ID_PATTERN);
      if (parts.length === 1) {
        result.push(node);
        continue;
      }
      parts.forEach((part, i) => {
        if (part === "") return;
        // Odd indices are captured ids. Only linkify an id that our graph
        // actually contains (grounded); an unknown/hallucinated id stays plain
        // text so it never becomes a clickable dead link. When no grounded set
        // is supplied (e.g. mock/offline), fall back to highlighting all.
        const isId = i % 2 === 1;
        if (isId && (!grounded || grounded.has(part.toUpperCase()))) {
          const mitreEl: Element = {
            type: "element",
            tagName: "mitre-id",
            properties: { id: part },
            children: [{ type: "text", value: part }],
          };
          result.push(mitreEl);
        } else {
          result.push({ type: "text", value: part });
        }
      });
    } else if (node.type === "element") {
      result.push({
        ...node,
        children: highlightChildren(
          node.children as RootContent[],
          insideLink || node.tagName === "a",
          grounded,
        ),
      } as Element);
    } else {
      result.push(node);
    }
  }

  return result;
}

// Wraps bare MITRE IDs (T1078, TA0006, G0016, ...) in <mitre-id> elements so
// MarkdownMessage can render them as tooltipped links - but never inside an
// existing <a>, since nested anchors are invalid HTML and break hydration.
export function rehypeMitreHighlight(grounded?: Set<string>) {
  return (tree: Root) => {
    tree.children = highlightChildren(tree.children, false, grounded) as Root["children"];
  };
}
