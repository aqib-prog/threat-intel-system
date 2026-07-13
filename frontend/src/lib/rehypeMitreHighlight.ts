import type { Root, RootContent, Element } from "hast";
import { MITRE_ID_PATTERN } from "./mitre";

function highlightChildren(children: RootContent[], insideLink: boolean): RootContent[] {
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
        if (i % 2 === 1) {
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
        children: highlightChildren(node.children as RootContent[], insideLink || node.tagName === "a"),
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
export function rehypeMitreHighlight() {
  return (tree: Root) => {
    tree.children = highlightChildren(tree.children, false) as Root["children"];
  };
}
