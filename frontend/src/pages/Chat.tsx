import { useEffect, useRef, useState } from "react";
import { motion } from "framer-motion";
import { Graph, WarningOctagon } from "@phosphor-icons/react";
import { ChatNavbar } from "../components/chat/ChatNavbar";
import { FilterSidebar } from "../components/chat/FilterSidebar";
import { FilterDrawer } from "../components/chat/FilterDrawer";
import { MessageBubble } from "../components/chat/MessageBubble";
import { CorrectionGate } from "../components/chat/CorrectionGate";
import { LoadingIndicator } from "../components/chat/LoadingIndicator";
import { InputBar } from "../components/chat/InputBar";
import { ScanlineOverlay } from "../components/effects/ScanlineOverlay";
import { ParticleNetwork } from "../components/effects/ParticleNetwork";
import { useChatHistory } from "../hooks/useChatHistory";
import { useConnectionStatus } from "../hooks/useConnectionStatus";
import { runQuery } from "../lib/api";
import type { ChatMessage } from "../lib/types";

const SESSION_REFRESH_MS = 60 * 60 * 1000;

export function Chat() {
  // Ambient background is mounted AFTER the page has painted.
  //
  // Arriving from the landing page means a WebGL context, two canvases, and a
  // video decode all starting inside the same frame as the route transition -
  // which is what makes the hand-off stutter. Deferring the decorative layer by
  // one idle callback lets the interactive UI paint first; the backdrop fades in
  // a moment later and nobody notices it was late.
  const [ambientReady, setAmbientReady] = useState(false);
  useEffect(() => {
    const idle =
      "requestIdleCallback" in window
        ? window.requestIdleCallback(() => setAmbientReady(true), { timeout: 800 })
        : window.setTimeout(() => setAmbientReady(true), 400);
    return () => {
      if ("cancelIdleCallback" in window) window.cancelIdleCallback(idle as number);
      else window.clearTimeout(idle as number);
    };
  }, []);

  const { messages, append } = useChatHistory();
  const connection = useConnectionStatus();
  const [pending, setPending] = useState(false);
  const [activeFilters, setActiveFilters] = useState<Record<string, unknown>>({});
  const [filtersDrawerOpen, setFiltersDrawerOpen] = useState(false);
  const [sessionExpired, setSessionExpired] = useState(false);
  // Id of the message whose spell-correction gate is awaiting a Yes/No. While
  // set, the input is disabled so the user must resolve the gate first.
  const [pendingCorrectionId, setPendingCorrectionId] = useState<string | null>(null);
  const bottomRef = useRef<HTMLDivElement>(null);
  const [preExistingIds] = useState<Set<string>>(() => new Set(messages.map((m) => m.id)));

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth", block: "end" });
  }, [messages.length, pending]);

  useEffect(() => {
    const lastAssistant = [...messages].reverse().find((m) => m.role === "assistant");
    if (lastAssistant?.filters) setActiveFilters(lastAssistant.filters);
  }, [messages]);

  useEffect(() => {
    const timer = window.setTimeout(() => setSessionExpired(true), SESSION_REFRESH_MS);
    return () => window.clearTimeout(timer);
  }, []);

  const handleSend = async (query: string, skipCorrection = false) => {
    // Note: no pendingCorrectionId guard here - the input is disabled in the UI
    // while a gate is open, and resolveCorrection calls this directly to answer.
    if (pending || sessionExpired) return;
    const userMessage: ChatMessage = {
      id: crypto.randomUUID(),
      role: "user",
      text: query,
      createdAt: Date.now(),
    };
    append(userMessage);
    setPending(true);

    const { data, isMock, error } = await runQuery(query, skipCorrection);

    // A pre-validated spell-correction: show a blocking "did you mean" gate
    // instead of the no-info answer, and disable input until the user chooses.
    if (data.correction) {
      const gateId = crypto.randomUUID();
      append({
        id: gateId,
        role: "assistant",
        text: "",
        createdAt: Date.now(),
        correction: data.correction,
      });
      setPendingCorrectionId(gateId);
      setPending(false);
      return;
    }

    const assistantMessage: ChatMessage = {
      id: crypto.randomUUID(),
      role: "assistant",
      text: data.answer || data.response,
      createdAt: Date.now(),
      filters: data.filters,
      nodes: data.nodes,
      allowed: data.allowed,
      guardrailCategory: data.guardrail_category,
      latencyMs: data.latency_ms,
      isMock,
      requestError: error,
      answerSource: data.answer_source,
      logEvidence: data.log_evidence,
      sections: data.answer_sections,
      presentation: data.answer_presentation,
      segments: data.segments,
      groundedIds: data.grounded_ids,
      suggestions: data.suggestions,
      suggestionActions: data.suggestion_actions,
      sourceQuery: query,
    };
    append(assistantMessage);
    setPending(false);
  };

  // Yes -> run the corrected query; No -> run the original. Both re-submit with
  // skip_correction so the guardrail + pipeline run again and no gate re-appears.
  const resolveCorrection = (query: string) => {
    setPendingCorrectionId(null);
    void handleSend(query, true);
  };

  return (
    <div className="relative flex h-dvh flex-col overflow-hidden bg-void">
      <div className="pointer-events-none fixed inset-0 z-0" aria-hidden="true">
        <div
          className="absolute inset-0"
          style={{
            background:
              "radial-gradient(ellipse 70% 50% at 50% -10%, rgba(124,58,237,0.1), transparent), radial-gradient(ellipse 50% 40% at 100% 100%, rgba(0,245,255,0.06), transparent)",
          }}
        />
        {/* Ambient film: the same network-graph footage as the landing hero,
            pushed far back (heavily dimmed, blurred, slowed) so the workspace
            feels alive without competing with the answer text. Muted + looping
            + playsInline so it never asks for permission or steals focus. */}
        {ambientReady && (
        <video
          className="absolute inset-0 h-full w-full object-cover opacity-[0.10] transition-opacity duration-700"
          src="/video/hero-scrub.mp4"
          poster="/video/hero-poster.jpg"
          autoPlay
          muted
          loop
          playsInline
          preload="metadata"
          aria-hidden="true"
          tabIndex={-1}
          // Heavier blur keeps only the soft bokeh blobs and discards the sharp
          // wireframe edges, which were the part competing with the text.
          style={{ filter: "blur(7px) saturate(135%) brightness(0.75)", transform: "scale(1.12)" }}
          ref={(el) => {
            // Quarter speed: ambient motion should drift, not race.
            if (el) el.playbackRate = 0.25;
          }}
        />
        )}
        {/* Centre-weighted scrim: near-opaque exactly where the conversation
            column sits, easing off toward the edges so the drifting blobs stay
            visible in the periphery instead of being flattened everywhere. */}
        <div
          className="absolute inset-0"
          style={{
            background:
              "radial-gradient(ellipse 62% 58% at 50% 46%, rgba(5,5,8,0.95) 0%, rgba(5,5,8,0.88) 42%, rgba(5,5,8,0.62) 72%, rgba(5,5,8,0.42) 100%)",
          }}
        />
        {/* Bloom pass: lifts the surviving blobs so they read as glowing motes
            rather than grey smudges, without raising the video's brightness. */}
        <div
          className="absolute inset-0 opacity-40"
          style={{
            background:
              "radial-gradient(ellipse 45% 35% at 18% 22%, rgba(0,245,255,0.10), transparent 70%), radial-gradient(ellipse 40% 32% at 82% 74%, rgba(124,58,237,0.10), transparent 70%)",
          }}
        />
        {ambientReady && (
          <div className="absolute inset-0 opacity-25">
            <ParticleNetwork />
          </div>
        )}
      </div>
      <ScanlineOverlay animated={false} />
      <div className="relative z-10">
        <ChatNavbar connection={connection} onToggleFilters={() => setFiltersDrawerOpen(true)} />
      </div>

      <div className="relative z-10 flex flex-1 overflow-hidden">
        <FilterSidebar filters={activeFilters} />
        <FilterDrawer
          open={filtersDrawerOpen}
          onClose={() => setFiltersDrawerOpen(false)}
          filters={activeFilters}
        />

        <main className="flex flex-1 flex-col overflow-hidden">
          {sessionExpired && (
            <div
              role="alert"
              className="flex items-center justify-center gap-3 border-b border-red/35 bg-red/12 px-4 py-3 text-center font-mono text-xs uppercase tracking-[0.16em] text-red shadow-[0_0_28px_-12px_rgba(255,51,102,0.8)]"
            >
              <span className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full border border-red/35 bg-red/10 shadow-[0_0_18px_-6px_rgba(255,51,102,0.95)]">
                <WarningOctagon size={16} weight="bold" aria-hidden="true" />
              </span>
              <span>
                Session has been open for 1 hour. Please refresh the page to start a fresh session.
              </span>
            </div>
          )}
          <div className="flex-1 overflow-y-auto px-4 py-6 sm:px-8">
            <div className="mx-auto flex w-full max-w-5xl flex-col gap-4">
              {messages.length === 0 && !pending && (
                <motion.div
                  initial={{ opacity: 0, y: 8 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ duration: 0.5, ease: "easeOut" }}
                  className="flex flex-col items-center justify-center gap-4 py-24 text-center"
                >
                  <span className="flex h-14 w-14 items-center justify-center rounded-full border border-cyan/25 bg-cyan/10 text-cyan shadow-[0_0_32px_-8px_rgba(0,245,255,0.4)]">
                    <Graph size={26} weight="bold" aria-hidden="true" />
                  </span>
                  <p className="font-mono text-xs uppercase tracking-[0.3em] text-text-dim">
                    No queries yet
                  </p>
                  <p className="max-w-sm font-mono text-sm text-text-mid">
                    Ask about threat actors, techniques, malware, or detection
                    strategies mapped in the graph.
                  </p>
                </motion.div>
              )}
              {messages.map((message) =>
                message.correction ? (
                  <CorrectionGate
                    key={message.id}
                    correction={message.correction}
                    answered={pendingCorrectionId !== message.id}
                    onConfirm={() => resolveCorrection(message.correction!.suggested)}
                    onReject={() => resolveCorrection(message.correction!.original)}
                  />
                ) : (
                  <MessageBubble
                    key={message.id}
                    message={message}
                    typewrite={!preExistingIds.has(message.id)}
                    onSuggestionClick={handleSend}
                  />
                )
              )}
              {pending && <LoadingIndicator />}
              <div ref={bottomRef} />
            </div>
          </div>

          <InputBar
            onSend={handleSend}
            disabled={pending || sessionExpired || pendingCorrectionId !== null}
            showChips={messages.length === 0}
          />
        </main>
      </div>
    </div>
  );
}
