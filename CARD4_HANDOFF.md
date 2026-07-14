# Handoff — Card 4: Real Auth System (JWT + Login/Signup)

Paste this whole file as your first message to resume/start this card.

## Project

`/Users/mohamedaqibabid/Desktop/threat-intel-graphrag/` — a Graph RAG threat-intelligence
chatbot over a MITRE ATT&CK knowledge graph in Neo4j. `frontend/` is React 19 + Vite +
Tailwind v4 + Framer Motion + react-three-fiber/drei (already installed) + D3. `backend/`
is FastAPI + Neo4j + Ollama (llama3.1).

Cards 1-3 are complete (bug fixes, chat UI redesign, deterministic log-analysis branch).
This is Card 4, standalone. No user database exists yet — you're building it from scratch.

## Ground rules (same as every prior card on this project)

1. **Do not touch** `backend/orchestration/pipeline.py`'s core logic, `backend/retrieval/guardrail.py`,
   `backend/retrieval/reranker.py`, `backend/retrieval/semantic_search.py`,
   `backend/retrieval/graph_traversal.py`, `backend/generation/generate.py`, `backend/ingestion/*.py`,
   or `backend/log_analysis/*.py` — this card is purely additive (new auth module + new
   frontend pages), it has no reason to touch the RAG/log-analysis pipeline at all.
2. **One task at a time.** Finish this card completely (implementation + full regression +
   real frontend verification), report results, then stop and wait for explicit go-ahead
   before anything else.
3. **Ask before connecting any new MCP/connector**, and **ask before settling for a
   lower-quality fallback** when a real asset/service would need one that isn't available
   (e.g. an email-sending service, a design-asset source) — don't silently downgrade.
4. **Test genuinely new scenarios** each round, not the same handful repeated. Cover the
   security-relevant edge cases explicitly (see checklist below), not just the happy path.
5. Clean up test/scratch files when done.
6. Give an honest confidence percentage for production-readiness when you finish, with
   real reasoning — don't overclaim "100% verified" if you only spot-checked.

## What's decided already (don't re-litigate)

- **Email + password, no email verification.** Simplest option, already chosen in a prior
  session specifically to avoid needing an external email-sending service. If "forgot
  password" comes up, that *would* need an email service — ask before adding one.
- Real per-user auth is entirely separate from `backend/security/auth.py`'s existing
  shared-secret API key scheme (that scheme is a bot/scanner deterrent for the public
  frontend bundle, not real auth — its own docstring says "for real per-user access
  control, put a session/JWT auth provider in front of this instead", which is exactly
  this card's job). Don't remove or repurpose it; JWT auth sits in front of / alongside it.

## Decisions you need to make or ask about (don't guess)

1. **User store.** No database for user accounts exists. Neo4j is the MITRE graph and
   should stay graph-only, not become a mixed user-data store. Recommend PostgreSQL for
   real relational user data (accounts, sessions/refresh-token records) — but this is a
   real infra decision (new dependency, new container/service to run locally and in
   deployment). **Ask the user to confirm or pick an alternative (SQLite for simplicity,
   if they'd rather avoid running Postgres locally) before building on it.**
2. Confirm password reset / "forgot password" is explicitly out of scope for this pass
   (since it needs an email service that isn't set up) unless the user says otherwise.

## Functional scope

- Signup: email + password → create account. Password confirmed client-side, validated
  server-side (see security checklist).
- Login: email + password → JWT access token + refresh token.
- Logout: invalidates the refresh token server-side (not just a client-side token drop).
- Auth-gated state in the frontend: know who's logged in, persist across a page reload,
  redirect appropriately (e.g. chat requires login, or however the user wants the gate
  scoped — ask if unclear).
- Token refresh flow: access token expires short (e.g. 15 min), refresh token longer
  (e.g. 7-30 days), silent refresh via a refresh endpoint.

## Design requirement — this must not look like a generic auth form

The existing product has a distinctive, fully custom dark "threat-intel terminal"
aesthetic. The login/signup screens must match it exactly, not be a bolted-on generic
form. Read these files first to internalize the system before writing any UI:

- `frontend/src/index.css` — the actual design tokens (`@theme` block): colors
  (`--color-void`, `--color-cyan #00f5ff`, `--color-green #00ff88`, `--color-red #ff3366`,
  `--color-purple #7c3aed`, `--color-amber #ffd700`, border/text-dim tokens), fonts
  (Space Grotesk display, JetBrains Mono for anything code/id/timestamp-flavored),
  `pulse-glow`/`scan`/`blink` keyframes.
- `frontend/src/lib/colorTokens.ts` — the `AccentColor` system (`ACCENT_CLASSES`,
  `ACCENT_HEX`, `hexToRgba`) already used everywhere else; reuse it, don't invent new colors.
- `frontend/src/components/chat/MessageBubble.tsx` and `InputBar.tsx` — the established
  visual language: `corner-brackets` utility class, glow via `box-shadow` + radial-gradient
  overlay per accent color, `rounded-2xl`/`rounded-xl` panels on `bg-void-panel/80` with
  `backdrop-blur-sm`, mono uppercase tracking-wide badges/labels, Framer Motion
  enter/exit transitions (`initial`/`animate`/`exit` with `easeOut`, ~0.2-0.3s).
- `frontend/src/components/effects/` (`ParticleNetwork.tsx`, `MatrixRain.tsx`,
  `BackgroundStack.tsx`) — the existing ambient background effects used on the landing
  page; the auth pages should feel like they belong to the same product, not a different one.

**"As advanced as possible" — 3D directive:** `@react-three/fiber`, `@react-three/drei`,
and `three` are **already installed** (frontend/package.json) — they're used for existing
effects. Reuse them; don't add a second competing 3D/animation library. Ideas in the
spirit of the existing aesthetic (pick what fits, don't just cram all of them in for
the sake of it):
- A subtle 3D particle/network field behind the auth card (continuing the site's
  "knowledge graph" visual motif) that reacts gently to cursor movement.
- A holographic/glass-morphic 3D card tilt effect on the login/signup panel itself
  (drei's `<Float>` or a manual perspective-tilt-on-mouse-move), kept subtle — this is a
  security-sensitive form, not a game; motion should read as "premium," not distracting.
- Micro-interactions: input focus states with the cyan glow already established,
  a satisfying success-state animation on successful auth (not a jarring redirect).
Respect `prefers-reduced-motion` (see `frontend/src/hooks/useReducedMotion.ts`, already
used elsewhere) for all of it.

If you want a *new* 3D/design asset (not code, an actual visual asset) and no existing
tool can produce it well, **ask before substituting a lower-quality placeholder** — same
standing rule as prior cards.

## Security requirements — this is the actual hard part, treat it as such

This card's bar is "production-level," not "good enough for a demo." Work through all of
these, don't cherry-pick:

**Password handling**
- Hash with **bcrypt or argon2id** (argon2id preferred if available) — never anything
  weaker, never a fast general-purpose hash (MD5/SHA-family alone).
- Enforce a real minimum password policy server-side (length ≥ 12 recommended; consider
  checking against a common-password/breached-password list rather than arbitrary
  complexity rules like "must contain a symbol," which push users toward weaker patterns).
- Never log passwords, even hashed ones, even in error paths.

**Tokens & sessions**
- JWT access token: short-lived (e.g. 15 min), signed with a strong secret (or asymmetric
  keys if you want refresh tokens verifiable across services) pulled from environment
  config — never hardcoded, never committed.
- Refresh token: longer-lived, stored server-side (a sessions/refresh-tokens table) so it
  can be **revoked** on logout or on suspected compromise — a JWT-only refresh scheme
  that can't be invalidated server-side is not acceptable here.
- Store tokens in **httpOnly, Secure, SameSite=Strict (or Lax if cross-site flows are
  needed) cookies**, not `localStorage`/`sessionStorage` — this closes off the most common
  XSS-to-token-theft path. If you deviate from this, explain why and get sign-off first.
- Rotate refresh tokens on use (refresh-token rotation) so a stolen-but-unused refresh
  token becomes invalid once the legitimate client refreshes.

**Transport & request hardening**
- Reuse the existing `slowapi` rate-limiting setup (`backend/security/rate_limit.py`,
  `backend/api/app.py`'s `@limiter.limit(...)` pattern) on `/auth/login`, `/auth/signup`,
  and `/auth/refresh` specifically — these are brute-force/enumeration targets and need
  tighter limits than general API endpoints.
- Add login throttling/lockout per-account (not just per-IP) after repeated failures, with
  a sane backoff — don't let it become a denial-of-service vector against a known email.
- CSRF protection appropriate to the cookie strategy chosen above (e.g. double-submit
  cookie or `SameSite` cookies plus a CSRF token for state-changing requests).
- Generic error messages on login failure — **never reveal whether the email exists**
  ("Invalid email or password" for both wrong-password and no-such-account cases) to
  prevent user enumeration. Apply the same care to signup ("if this email isn't already
  registered, check your inbox" style responses are for the verification flow we're
  *not* building — for signup without verification, still avoid leaking exact reasons
  where it matters, e.g. timing differences between "email taken" and "email available"
  checks).
- Constant-time comparison for anything that compares secrets (most JWT/password
  libraries already handle this — just don't hand-roll a comparison).

**Input validation**
- Server-side email format validation (don't trust client-side alone).
- Sanitize/validate all auth inputs against injection (this is a FastAPI + presumably
  SQL/Postgres or similar backend — use parameterized queries / an ORM, never string-built
  SQL).

**Config & secrets**
- JWT signing secret, DB credentials, etc. via environment variables following this repo's
  existing pattern (`backend/.env.*.example` files, `api/settings.py`'s `env_str`/`env_int`
  helpers) — add new `.env.*.example` entries for whatever you introduce, matching the
  existing style (dev/staging/production variants).
- Add a rotated-secret note to `DEPLOYMENT.md` if you touch deployment-relevant config,
  matching its existing style.

**OWASP Top 10 pass** — explicitly check each of these applies-or-doesn't for what you build:
Broken Access Control, Cryptographic Failures, Injection, Insecure Design, Security
Misconfiguration, Vulnerable Components, Auth Failures (this whole card), Data Integrity
Failures, Logging/Monitoring Failures, SSRF. Most are N/A for a scoped auth feature, but
state that explicitly rather than silently skipping the pass.

## Testing standard to hold this to

Cover, with genuinely distinct test cases (not just happy-path signup+login):
- Signup: valid signup, duplicate email, weak password rejected, malformed email rejected,
  SQL-injection-shaped input in email/password fields, very long input (DoS-shaped),
  Unicode/emoji in fields.
- Login: correct credentials, wrong password, nonexistent email (verify identical error
  message/timing to wrong-password case), account lockout after N failures, login while
  already logged in.
- Tokens: access token expiry actually enforced, refresh flow works, refresh token
  rotation invalidates the old one, logout actually revokes the refresh token server-side
  (verify a captured pre-logout refresh token can't be reused after logout), tampered/
  malformed JWT rejected, JWT signed with wrong secret rejected.
- Rate limiting: confirm login/signup/refresh actually throttle under repeated calls.
- Frontend: full signup→login→refresh→logout flow driven in the real browser (not just
  curl), responsive/mobile check, `prefers-reduced-motion` respected, dark theme only
  (this site doesn't have a light mode — confirm nothing assumes one).

Report pass/fail honestly per category, not just an aggregate number.

## Before writing code

Resolve the two open decisions above (user store choice; forgot-password out-of-scope
confirmation) with the user first. Then proceed.
