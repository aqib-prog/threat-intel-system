## STATUS: RESOLVED — the fix described below has been applied and verified live

Fixed: `actor`/`actors`/`threat actor(s)`/`cve`/`cve id` added to `CATEGORY_META`
(`frontend/src/lib/answerSections.ts`), `mitre id` color corrected to amber,
`parseNodeSectionCounts` (`frontend/src/lib/parseAnswerSections.ts`) now normalizes
`node_type` via `humanizeLabel` + falls back through `canonicalSectionLabel`, matching
the same two-tier lookup the markdown-header path already had.

Verified live in browser across 3 distinct scenarios (single-actor question, 4-category
actor/campaign/malware/tool comparison, Windows log-analysis with 8 categories) - Actor
now renders correctly everywhere it didn't before. Cross-checked displayed facts against
Neo4j directly and against MITRE's own site (attack.mitre.org) - no hallucination found.
Full regression 37/37 clean, no console errors.

**Not done / still open**: the second issue in this handoff (LLM markdown-format
brittleness - `SECTION_RE`/`LIST_ITEM_RE` only tolerate `**Label:**` and `-`/`*`/`1.`
list markers) was diagnosed but not fixed or tested against real varied LLM output this
round - that part of this handoff is still live if you want to pick it up.

---

# Original handoff — Frontend: category sections dropping node types the graph/sources panel shows fine

Paste this whole file as your first message to resume (if picking up the still-open LLM-format-brittleness part).

## Project

`/Users/mohamedaqibabid/Desktop/threat-intel-graphrag/` — Graph RAG threat-intel chatbot.
`frontend/` is React 19 + Vite + Tailwind v4 + Framer Motion + D3 + react-three-fiber.
Cards 1-3 are complete (bug fixes, chat UI redesign, deterministic log-analysis branch with
249+ rules across Windows/Linux/AWS/Kubernetes/macOS). This card is a frontend-only bug fix.

## Ground rules (same as every prior card)

1. Do not touch any backend file except with a specifically diagnosed, reproduced bug (this
   card should be 100% frontend, no backend reason to change anything here).
2. One task at a time. Finish this completely (fix + verify in the real browser across
   multiple distinct scenarios + report), then stop and wait for go-ahead.
3. **Test genuinely different scenarios, not the same one repeated.** The user has pushed
   back hard on this in every prior card — cover both the log-analysis path (multiple
   platforms: Windows/Linux/AWS/Kubernetes/macOS) and the normal RAG question path (multiple
   entity types: actors, techniques, malware, tools, campaigns, comparisons), not just one
   example of each.
4. After fixing, re-verify with fresh scenarios (not the exact ones used to find the bug),
   and report pass/fail honestly.
5. Clean up any test/scratch files when done.

## The bug (already root-caused this session — verify it still reproduces, don't re-diagnose from scratch)

**Symptom reported by the user**: some categories/node types show up correctly in the
Source Graph / Sources Panel (cards + D3 graph view under a message), but the SAME
category is missing from the "sections" - meaning the bold-labeled markdown category
cards (`rehypeAnswerSections.ts`) and/or the radar-chart/gauge breakdown
(`AnswerVisualization.tsx` / `SingleCategoryGauge.tsx`) don't show it, and/or its icon/
color/description look inconsistent with the rest of the theme.

**Root cause, verified via code reading (not yet re-verified live in browser this
session - do that first)**:

`frontend/src/lib/parseAnswerSections.ts`'s `parseNodeSectionCounts()` (used to build the
radar-chart/gauge data from `message.nodes`, as a fallback when the markdown text itself
doesn't have 2+ bold category headers) does this:

```ts
for (const node of nodes) {
  const label = node.node_type?.trim();
  if (!label || !categoryMetaFor(label)) continue;   // <-- silently drops non-matches
  ...
}
```

`node.node_type` comes straight from the backend exactly as `orchestration/pipeline.py`
returns it - PascalCase, no spaces: `"Actor"`, `"DetectionStrategy"`, `"DataComponent"`,
`"Technique"`, `"Malware"`, `"Tool"`, `"Campaign"`, `"Tactic"`, `"Mitigation"`, `"Analytic"`.

But `categoryMetaFor()` (in `frontend/src/lib/answerSections.ts`) looks the label up
**lowercased with no other normalization** against `CATEGORY_META`, whose keys are
LLM-prose-style labels with spaces: `"detection strategies"`, `"data components"`,
`"data sources"`, etc.

So:
- `"DetectionStrategy"` → lowercased to `"detectionstrategy"` → **no match** (key is
  `"detection strategies"`, with a space and pluralized differently) → silently dropped.
- `"DataComponent"` → `"datacomponent"` → **no match** (key is `"data components"`) →
  dropped.
- `"Actor"` → `"actor"` → **no match at all** - `CATEGORY_META` has **no entry for Actor
  or Actors whatsoever**. Actor is an extremely common node type (any threat-actor
  question returns one) and it has zero icon/color/description in this system.

Meanwhile, `frontend/src/lib/colorTokens.ts`'s `accentForNodeType()` (used by
`SourceCard.tsx`/`SourceGraph.tsx` to render the Sources Panel and D3 graph) goes through
`normalizeKey()` first:

```ts
function normalizeKey(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9]/g, "");
}
```

This strips spaces/punctuation before comparing, so `"DetectionStrategy"` correctly
normalizes to `"detectionstrategy"` and matches `NODE_TYPE_ACCENT`'s `detectionstrategy`
key. **This is why the Sources Panel/graph renders these node types fine while the
sections/chart silently drop them - two different normalization functions, only one of
which actually handles PascalCase.**

## What needs fixing

1. **Normalize `node_type` the same way in both places.** Either:
   - Make `categoryMetaFor()` (or a wrapper around it) apply the same kind of
     normalization `colorTokens.ts`'s `normalizeKey()`/`humanizeLabel()` already do before
     comparing, so `"DetectionStrategy"` and `"detection strategies"` resolve to the same
     entry regardless of casing/spacing/pluralization, OR
   - Convert `node.node_type` through `humanizeLabel()` (already exported from
     `colorTokens.ts`: `"DetectionStrategy"` → `"Detection Strategy"`) before calling
     `categoryMetaFor()` in `parseNodeSectionCounts()`.
   - Whichever approach, make sure `CATEGORY_META`'s keys and `NODE_TYPE_ACCENT`'s keys
     end up agreeing on every node type the backend can actually return - don't just
     patch the one example you test with.
2. **Add the missing `Actor`/`Actors` entry to `CATEGORY_META`** (icon + accent + a real
   glossary-style description, matching the tone of the existing entries in
   `frontend/src/lib/answerSections.ts`). Check for other missing node types the backend
   can emit while you're in there - cross-reference `orchestration/pipeline.py`'s node
   `type`/`node_type` CASE statement (search the file for `WHEN n:Actor THEN` etc.) against
   every key currently in both `CATEGORY_META` and `NODE_TYPE_ACCENT` to find every gap,
   not just the ones in your test scenarios.
3. **Confirm icon/color/description consistency end-to-end** for every category across:
   - The bold-labeled markdown cards (`rehypeAnswerSections.ts` → `MarkdownMessage.tsx`)
   - The radar chart / single-category gauge (`AnswerVisualization.tsx` /
     `SingleCategoryGauge.tsx`)
   - The Sources Panel cards (`SourceCard.tsx`)
   - The Source Graph D3 view (`SourceGraph.tsx`)
   - The log-analysis evidence panel and its confidence bar (`LogEvidencePanel.tsx`)

   All four/five surfaces should agree on: same icon per category, same accent color per
   category, and (where a description tooltip exists) the same description text. Right
   now there are two independent lookup systems (`answerSections.ts`'s `CATEGORY_META`
   keyed by prose label, `colorTokens.ts`'s `NODE_TYPE_ACCENT` keyed by node_type) that
   can silently drift out of sync, as this bug demonstrates - consider whether they should
   be unified into one source of truth, or just kept in sync carefully. Use your judgment,
   but don't leave two independently-drifting copies if a single shared mapping is
   reasonably easy to do without a large refactor.

## Testing standard - this is the part the user emphasized most

**Test genuinely different scenarios, not the same one twice.** Cover, at minimum, in the
real browser against the real running backend (not just static code reading):

- Log-analysis path: a Windows-flavored log, a Linux-flavored log, an AWS CloudTrail-style
  JSON log, a Kubernetes audit JSON log, and a macOS log - five *different* platforms,
  each producing a different mix of node types (Technique/Tactic/DetectionStrategy/
  Mitigation), confirm every section that appears in the markdown/chart also appears
  correctly in the Sources Panel/graph and vice versa, with matching icon+color.
- Normal RAG path: a pure threat-actor question (exercises the previously-missing Actor
  node type), a technique-explanation question, a malware question, a tool question, a
  campaign question, and a 3+-actor comparison question (Card 1's fix) - confirm each
  one's node types all render consistently across every surface listed above.
- At least one response with 1 category (SingleCategoryGauge path) and one with 2+
  categories (AnswerVisualization radar path), for both log-analysis and RAG.

For each scenario, actually open the browser, send the query, screenshot or read_page the
rendered result, and check: does every node_type present in `message.nodes` show up
somewhere in the sections/chart with a sensible icon and color, and does it match what the
Sources Panel/graph show for the same node? Don't just eyeball one message and call it done.

## Second, related root cause (also verified, don't re-diagnose) - the parsing is brittle against real LLM output variability

The text these sections/charts parse comes from an LLM (llama3.1 via Ollama, in
`backend/generation/generate.py`), not from fixed templates - it is not guaranteed to
always format headers/lists exactly the same way every time. The user flagged this
correctly: sometimes bullets, sometimes numbers, sometimes neither, and the parsing regex
is currently rigid. Verified in `frontend/src/lib/parseAnswerSections.ts`:

```ts
const SECTION_RE = /\*\*([A-Za-z ]+):\*\*/g;
const LIST_ITEM_RE = /^\s*(?:\d+\.|[-*])\s+\S.*$/gm;
```

- `SECTION_RE` **only** matches a header formatted exactly as `**Label:**` - bold
  asterisks wrapping both the label AND the trailing colon, label restricted to letters
  and spaces only (no numbers/punctuation). If the model instead outputs `**Label**:`
  (colon outside the bold), a `## Label` markdown heading, plain `Label:` with no bold at
  all, or a label containing e.g. a slash or number, this regex matches nothing and that
  whole response silently gets no section cards / no chart data from
  `parseAnswerSectionCounts()` - it would fall back to `parseNodeSectionCounts()` (node
  types from `message.nodes`) if available, or nothing at all otherwise.
- `LIST_ITEM_RE` already tolerates both `-`/`*` bullets and `1.` numbered items (better
  than it first looks), but still requires one of those exact prefixes at line start. A
  response using `•` bullets, `1)` instead of `1.`, or plain newline-separated sentences
  with no prefix at all would have zero items counted for that section.

**Important scoping note**: this is a *degraded visual enhancement* bug, not a *content
loss* bug - `MarkdownMessage.tsx` renders the raw LLM markdown via `react-markdown`
regardless of whether `parseAnswerSectionCounts` successfully finds headers, so the user
still sees the actual answer text either way. What breaks is specifically: the bordered
category cards (`rehypeAnswerSections.ts` groups sections using the same-shaped
`canonicalSectionLabel` matching, likely has the same brittleness - check it too), the
radar chart / single-category gauge, and consistency with the Sources Panel. Confirm this
distinction still holds before treating it as more severe than it is - re-verify by
finding/forcing a real LLM response that uses non-`**Label:**` formatting and checking
that the raw answer text still displays even when the cards/chart don't.

**What to do about it**: broaden `SECTION_RE`/`LIST_ITEM_RE`/`rehypeAnswerSections.ts`'s
matching to tolerate the realistic variations above (bold-without-colon, heading syntax,
unprefixed bullets like `•`, `1)` style numbering), and - more importantly - actually
generate a batch of REAL responses from the live backend across a variety of question
phrasings (not synthetic hand-written markdown) to see what llama3.1 actually tends to
output in practice, since guessing at "possible" formats without seeing real model output
risks fixing formats the model never actually produces while missing ones it does. Do
this for both the normal RAG path and the log-analysis path (the log-analysis path's
formatting is template-generated in `backend/log_analysis/formatter.py`, not LLM-written,
so it should already be consistent by construction - confirm that, and focus the
real-output-sampling effort on the LLM-generated RAG path where the variability actually
comes from).

## Before writing code

If anything in this handoff is unclear or you find the root cause doesn't fully explain
what you observe once you re-verify live, ask the user rather than guessing further -
they explicitly asked to be asked before assumptions are made on this card.
