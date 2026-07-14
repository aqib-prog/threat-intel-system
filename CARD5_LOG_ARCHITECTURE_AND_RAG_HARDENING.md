# Card 5: Production-Grade Log Detection Architecture + RAG Hardening

**Priority order (explicit, per user instruction):** Part 1 (log-analysis architecture) ships and is validated first. Part 2 (RAG/guardrail hardening) starts only after Part 1's numbers have been reviewed. Quality over speed — no phase should be skipped or rushed to "finish."

---

## 0. Why this card exists

Current honest confidence: **log analysis ~70%, normal RAG ~90%** (see prior session). The log-analysis number is capped by an architectural ceiling, not a bug list — the fixes so far (windowing, `.exe` tolerance, guardrail determinism, etc.) were all real but incremental. This card designs the actual structural fix, grounded in verified facts about the candidate tools (not assumptions — see §1.1), with a phased roadmap that measures before it builds, so we don't over-invest in a rebuild the data says isn't needed.

**Ground rule for the whole card (explicit instruction):** no phase gets built until it's been proven on a small sample first. Every layer below has a "prototype small, verify by hand, then scale" checkpoint — the goal is 100% confidence per step before spending real engineering effort on the full build, not speed.

**Scope note:** AWS and Kubernetes rule sourcing (originally sketched as a separate "Card 6") is folded into this card's Part 1 — both platforms are part of the same architecture overhaul, not a follow-on. **Part 1 is not considered done until its final objective is met: every newly-covered scenario (Windows/Linux/macOS/AWS/Kubernetes) is verified end-to-end through the actual frontend, rendering correctly in the existing category/chart/color system with no regressions** — see §1.6.

---

## Part 1: Log-Analysis Architecture Overhaul

### 1.0 Why the current approach has a ceiling

- **Our Sigma YAML parser is hand-rolled and only understands a subset of Sigma's modifiers** (`|all` as AND, a plain list as OR, `endswith` with a boundary). Real Sigma rules use `contains|all`, `base64offset`, `windash`, `cidr`, `re` (+flags), field comparisons, `1 of selection*`, arbitrarily nested `and`/`or`/`not`. We only ever extracted the subset of rules that happened to fit our narrow parser — and even within that subset, found and fixed 3 real parsing bugs this session (OR/AND confusion, lookahead precedence, quote-escaping). That's the tell that hand-rolling a spec-compliant parser is the wrong layer to keep patching.
- **Detection matches raw full-line text via regex, never structured fields.** Two vendors naming the same concept differently (Windows `CommandLine` vs. Linux `exe`+argv reconstruction vs. CloudTrail `requestParameters`) each need their own hand-written regex, forever, per format variant encountered. This — not "not enough rules extracted yet" — is the real reason coverage tops out around 222/600+ techniques and why untested log formats (raw Sysmon XML, CEF, LEEF, vendor SIEM exports) are a known blind spot.
- **No empirical validation exists.** High/medium/low confidence buckets are subjective judgment calls carried over from Sigma's own `level` field plus our own reasoning — never checked against real logs with known ground truth, and false-positive rate has never been measured against a corpus of benign logs.

### 1.1 Verified facts about the three tools (researched today — not assumptions)

**pySigma** (`pip install pysigma`, inspected the actual installed source, not just docs):
- Exposes a fully structured, **already-correctly-parsed** condition tree. Confirmed by parsing a real rule (`selection and not filter`) and inspecting `rule.detection.parsed_condition[0].parsed`: it returns a proper `ConditionAND`/`ConditionOR`/`ConditionNOT` boolean tree with leaf `ConditionFieldEqualsValueExpression` nodes carrying `.field` and `.value` (values are `SigmaString`/`SigmaNumber` objects with explicit `SpecialChars.WILDCARD_MULTI`/`WILDCARD_SINGLE` markers instead of raw `*` — wildcard handling is already normalized).
- **No backend/SQL/query-language is required to use this.** We can walk the parsed tree ourselves and emit our own lookahead-based regex per leaf, exactly like today — just from a tree that Sigma's own maintainers parse correctly, instead of a boolean-condition string we hand-parse ourselves.
- Confirmed full modifier support by reading `sigma/modifiers.py` directly: `contains`, `startswith`, `endswith`, `base64`, `base64offset`, `wide`, `windash`, `re` (+ ignorecase/multiline/dotall flags), `cidr`, `all`, compare (`lt`/`lte`/`gt`/`gte`), `fieldref`, `exists`, `expand`, plus timestamp-granularity modifiers. This is every modifier Sigma's spec defines — our hand-rolled parser understood maybe 3 of these.
- `SigmaCollection.load_ruleset(paths, collect_errors=True)` bulk-loads an entire directory tree of YAML rules with per-rule error isolation (one malformed rule doesn't kill the batch) — replaces our fragile sparse-clone-and-scrape scripts.

**OSSEM** (checked the actual repo structure):
- Confirmed: **specification and data dictionaries only, no runnable parser code.** The Common Data Model (CDM) defines canonical field names and schema entities across Windows/Linux/macOS/cloud as documentation, meant to guide someone else's parser design — it is not a library we import. Its only value to us is as a naming reference when we design our own canonical event schema in Layer 2 below.

**Security-Datasets** (checked via GitHub API + fetched a real metadata file):
- Confirmed real attack log captures (`datasets/atomic/{windows,linux,aws}/<tactic>/{host,network}/*.zip`), each accompanied by a YAML metadata file with **explicit ground truth**: e.g. `attack_mappings: [{technique: T1069, sub-technique: "001", tactics: [TA0007]}]`, plus a description of exactly what was simulated. This is a genuine labeled validation corpus — real logs, known correct answer — which we currently have zero of (all our testing so far has been against logs we crafted ourselves, which can't catch blind spots we don't already know about).

**AWS/Kubernetes rule sources — verified, with one earlier claim caught and rejected:**
A user-supplied source list named four repos for AWS/Kubernetes coverage. Checked each directly against the GitHub API before trusting any of it:
- ✅ **`SigmaHQ/sigma`, real path `rules/cloud/aws/cloudtrail/`** (not `/rules/aws/` as claimed) — confirmed 55 real AWS CloudTrail detection rules, reachable via the same pySigma pipeline as Layer 1 below.
- ❌ **Sigma "Kubernetes rules"** — does not exist. Checked `/rules/kubernetes/`, `/rules/cloud/kubernetes/`, and other plausible paths; all 404. Sigma has no Kubernetes-specific content.
- ❌ **`hacksploit/AWS-Security-Log-Analysis`** — repo does not exist (404, no close match in search). Fabricated.
- ❌ **`cyberark/kubernetes-sinkhole`** — repo does not exist (404). CyberArk does have real K8s repos (`KubiScan`, `kubernetes-rbac-audit`) but they're privilege-escalation scanning tools, not log-detection rule sets, and not this name. Fabricated.
- ✅ **`falcosecurity/plugins`** (real, checked directly, 9,150+ stars on the parent `falco` project) — this is the actual fix for the Kubernetes gap:
  - **`plugins/k8saudit/rules/k8s_audit_rules.yaml`** — confirmed **48 real Kubernetes audit-log rules** (privileged pods, sensitive host mounts, hostNetwork/hostPID pods, disallowed users/images, etc.) — fetched and read the actual file.
  - **`plugins/cloudtrail/rules/aws_cloudtrail_rules.yaml`** — confirmed **22 more AWS rules**, on top of Sigma's 55 — a bonus second source for AWS.
  - License: Apache-2.0 — fine to use as a reference/compile source.
  - **Caveat 1 — different rule language.** Falco rules use their own condition DSL (`ka.user.name`, `ka.req.pod.containers.image`, `evt.type`, macros/lists composed with `and`/`or`/`not`) — not Sigma YAML. **pySigma cannot parse these.** A small, separate Falco-condition parser is needed (simpler grammar than Sigma's modifier system, but still new work, not a drop-in reuse of Layer 1).
  - **Caveat 2 — no MITRE technique tags.** Checked every rule's `tags:` field in `k8s_audit_rules.yaml` — all just say `[k8s]` or `[k8s, network]`, no ATT&CK technique/tactic reference (unlike Sigma, which often carries this in its rule metadata). Each of the 48 rules will need **manual mapping** to the closest Containers-platform MITRE technique, by reading its description — real effort, but far less than hand-building 48 rules from scratch (we've already hand-built 7 K8s rules this way).

### 1.2 Target architecture — 4 layers

**Layer 1 — Rule Compilation (two sources, two small parsers, one output format).**

*1a. Sigma → pySigma compiler* (Windows, Linux, macOS, AWS CloudTrail).
Replace the *offline extraction script* (not a runtime dependency) that builds `mappings.py`'s rule lists with a pySigma-powered version: `load_ruleset()` over the sparse-cloned Sigma repo (now including `rules/cloud/aws/cloudtrail/`) → walk each rule's `parsed_condition` tree → emit our existing lookahead-composed regex per leaf, driven by a spec-correct parse instead of hand-parsed YAML → also read `logsource.product`/`category`/`service` to auto-classify platform instead of manual per-rule assignment.

*1b. Falco → small custom compiler* (Kubernetes primarily, AWS as a bonus second source).
Sparse-clone `falcosecurity/plugins` (`plugins/k8saudit/rules/`, `plugins/cloudtrail/rules/`). Write a small parser for Falco's condition DSL (boolean `and`/`or`/`not` over `macro`/`list` definitions and `ka.*`/`evt.*` field comparisons — a much smaller grammar than Sigma's, prototype on the first 5 rules before trusting it on all 70). Since these rules carry no MITRE tags, each compiled rule needs a **manual technique mapping pass** (read the rule's `desc:`, match to the closest Containers-platform ATT&CK technique, same process already used for our 7 hand-built K8s rules) before it's added to `mappings.py`.

Both 1a and 1b emit into the **same `MappingRule` format** `mappings.py` already uses — the rest of the pipeline (detector/parser/analyzer/formatter) doesn't need to know which source a rule came from.

Recommendation: keep both as **offline compilers**, not live runtime dependencies — output is still a reviewable `mappings.py` diff before merging, and the running system stays dependency-free.
*Acceptance criteria:* regenerate the rule set from both sources, diff against current `mappings.py`, spot-check a sample of newly-covered rules against MITRE by hand (Sigma rules *and* the manually-mapped Falco rules), confirm regression suite still green, confirm a material increase in unique techniques covered (target 400+ overall, stretch 500+; Kubernetes specifically should go from 7 hand-built rules to ~48).

**Layer 2 — Structured Field Extraction / Canonical Event Model (the actual fix for format diversity).**
This is the big lift and the one most likely to need real iteration — budget real time, validate per-platform, don't rush it.
- Design a canonical event schema (Python dict/dataclass) informed by OSSEM's CDM naming, but scoped to only the ~15-20 fields our rules actually reference (`process.command_line`, `process.parent.name`, `user.name`, `network.source_ip`, `event.id`, etc.) — not OSSEM's full breadth.
- Build **one platform's extractor at a time**, starting with Windows (most rules today): raw pasted log (any sub-format we already parse — KV lines, JSON, windowed multi-line) → best-effort canonical event dicts; missing fields stay absent, never fabricated.
- Detection becomes **hybrid**: try structured-field matching first when the platform's extractor produced fields, but **always keep today's raw-text regex match running too** — a strict superset, never a replacement, until structured matching is proven at least as good.
*Acceptance criteria:* Windows extractor pilot must show a measurable precision/recall improvement (see Layer 3) over current text-regex-only baseline before repeating for other platforms.

**Layer 3 — Confidence Calibration & Validation (Security-Datasets-driven).**
- Pull a curated subset (~30-50 samples spanning multiple tactics, Windows first) into a local test-fixture directory — fetched on demand, gitignored, not committed (check the repo's LICENSE before ever redistributing sample data inside our own repo).
- For each sample: run through detector+analyzer, compare predicted technique(s) against the sample's `attack_mappings` ground truth. Compute precision/recall/F1 per platform and per confidence bucket.
- Separately source or synthesize a batch of **known-benign** logs (normal admin activity, non-attack Sysmon noise) to measure real false-positive rate — something we've never actually measured.
*Acceptance criteria:* documented precision/recall numbers per platform. Proposed first bar: 80% precision / 60% recall — revisit with user once real numbers are in hand.

**Layer 4 — Test/CI Harness.**
Formalize the current ad hoc scratchpad `regression.py` into a committed, repeatable suite (location TBD against project convention) including both existing synthetic cases and the Security-Datasets-derived cases from Layer 3, so none of this regresses silently in a future session.

### 1.3 Phased roadmap — small steps, checkpoint before proceeding

1. **Prototype** the pySigma-based compiler on a small sample (10-20 Windows rules). Hand-validate output regex against a few real Security-Datasets logs. → *checkpoint: show a diff sample before scaling up.*
2. **Full Sigma recompilation** across Windows/Linux/macOS/AWS-CloudTrail categories we target. Diff against current `mappings.py`, run regression. → *checkpoint: report rule-count delta + regression results.*
3. **Prototype** the Falco condition-DSL parser on 5 rules (mix of k8saudit + cloudtrail). Hand-validate the generated regex/logic against the rule's own `desc:` and a hand-crafted sample log. → *checkpoint: show the sample before scaling up.*
4. **Full Falco recompilation** (48 k8saudit + 22 cloudtrail rules) + the manual MITRE-technique mapping pass for the 48 K8s rules. → *checkpoint: report the mapping table for review before merging into `mappings.py`.*
5. **Pull the Security-Datasets validation corpus** (Windows first, expand to AWS if time permits) and measure baseline precision/recall using the **current** (pre-Layer-2) detection approach, now including the newly-compiled Sigma+Falco rules. → *checkpoint: report honest numbers — this tells us how much Layer 2 actually buys us before committing to building it.*
6. **Decide with user**, based on step 5's numbers, whether Layer 2 is worth its cost or whether Layer 1 + calibration alone already clears the bar.
7. If proceeding: build the **Windows** extractor end-to-end, hybrid-fallback matching, re-run the validation corpus, compare the precision/recall delta against step 5's baseline. → *checkpoint before repeating per platform.*
8. Repeat step 7 per remaining platform **only if** the Windows pilot shows clear improvement.
9. Formalize Layer 4 as a permanent regression gate.
10. **Final objective — frontend verification (see §1.6).** Only after all of the above is stable does Part 1 get marked done.

This lets us stop after step 5 or 6 if the data says Layer 1 + calibration is already sufficient — the whole point is to measure before over-building, per the "small mistake → big rework" risk flagged.

### 1.4 Risk register

- **pySigma dependency:** offline-compiler-only use = zero runtime risk. Only becomes a real dependency to pin/audit if we ever move rule compilation to run live.
- **Falco parser correctness:** this is new, hand-written parsing code (no official library to lean on like pySigma) — keep it deliberately small in scope (only the constructs actually used across the ~70 rules we're compiling, not a general Falco-DSL engine), and hand-verify every prototype output before scaling, same discipline that caught our 3 Sigma-parser bugs earlier.
- **Falco→MITRE manual mapping risk:** since there's no source-of-truth tag to lean on, mis-mapping a rule to the wrong technique is a real risk — cross-check every mapping against MITRE's own Containers matrix page before merging, not just our own judgment.
- **Security-Datasets licensing:** verify the repo's LICENSE before redistributing any sample data in our own repo; safer as an external fetch-on-demand fixture, gitignored.
- **Layer 2 scope creep:** per-platform structured extraction is genuinely hard (real SIEM vendors spend years on this) — stay scoped to only the fields our existing ~250+ rules reference; resist building a "generic" parser.
- **Regression discipline:** every step must keep the existing 37/37 + Sigma/Falco-expansion suite green; never trade an existing working capability for a new one.

### 1.5 Test discipline for every step above

No layer, no compiler, no rule batch gets merged without: (a) a small prototype run first, (b) hand-verification of its output against a known-correct reference (MITRE's site, a real Security-Datasets sample, or a hand-crafted log), (c) a full regression run showing zero regressions, before scaling to the next batch. This applies uniformly to Sigma compilation, Falco compilation, the MITRE-mapping pass, and Layer 2's per-platform extractors — no exceptions, per the explicit "100% confident before we build it" instruction.

### 1.6 Final objective — frontend verification (Part 1 isn't done until this passes)

Once Layers 1-4 are stable and validated on their own terms, the last step is confirming the **whole thing still looks and works right from the user's seat** — new rule sources must not silently break the frontend rendering work already done this project (category/color/icon consistency, the chart display logic for 1/2/3+ categories, the log-analysis badge/evidence panel).

- Run live, in-browser scenarios that specifically exercise the **new** coverage: a real Kubernetes audit-log paste that trips one of the 48 newly-compiled Falco rules, a real AWS CloudTrail paste that trips one of the Falco/Sigma-bonus rules, and at least one Windows/Linux scenario that now matches via a Sigma rule our old hand-rolled parser would have missed.
- For each: confirm the rendered answer's categories (Techniques, Tactics, Tools, Platforms, etc.) all resolve to a known icon/color/description in `answerSections.ts` / `colorTokens.ts` — no silently-dropped category, no generic fallback styling.
- Confirm the chart (`AnswerVisualization`) renders correctly for whatever category count results (1 → gauge, 2 → split bar, 3+ → radar — all three paths already fixed this project, but must be re-checked against genuinely new data shapes).
- Cross-validate at least one new technique match against Neo4j directly and against MITRE's own site (same method used earlier this project for APT29/FIN7), to confirm the new rule → technique → graph-node linkage is factually correct, not just cosmetically fine.
- Zero console errors, zero regressions in the 3 previously-verified scenarios (single-actor, multi-category, Windows log paste) re-run one more time as a sanity check.

Only when all of this passes does Part 1 get marked complete and Part 2 begins.

---

## Part 2: RAG / Guardrail Hardening (starts only after Part 1 ships and is validated)

### 2.1 Guardrail depth
Current: Layer 1 deterministic blacklist regex + Layer 2 LLM classifier (temperature=0, fixed this session). Known ceiling: a regex blacklist can't be complete by construction.
- Build a genuine red-team test corpus (~50-100 known jailbreak patterns: DAN-style, roleplay-wrapping, hypothetical-framing, encoding tricks, many-shot, language-switching) and measure Layer 2's actual catch rate systematically — today only ~12 variants have been spot-tested.
- Consider a 3rd layer: embedding-similarity search against a maintained corpus of known attack prompts, to catch semantically-similar-but-differently-worded attempts that neither regex nor a single-shot LLM classification reliably catches alone.

### 2.2 Retrieval/graph traversal audit
- Build a golden Q&A test set sourced directly from attack.mitre.org (not our own graph, to avoid circular validation) covering actor→technique, technique→tactic, technique→mitigation relationships.
- Run the full pipeline against this golden set; measure retrieval precision/recall and check generated answers for hallucination against the golden facts.
- Smaller in scope than Part 1 — mostly a test-harness + measurement effort, likely low code-change risk.

---

## Immediate next step

Steps 1-6 of the Part 1 roadmap (Sigma prototype → full Sigma recompile → Falco prototype → full Falco recompile + manual mapping → validation corpus → go/no-go decision on Layer 2) are all small, checkpoint-gated, and will honestly tell us whether Layer 2's bigger rebuild is even necessary before we commit real time to it. Recommended starting point for the next work session: step 1.
