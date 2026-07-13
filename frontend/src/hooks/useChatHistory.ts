import { useCallback, useState } from "react";
import type { ChatMessage } from "../lib/types";

export function useChatHistory() {
  // Intentionally in-memory only: refreshing the page starts a clean chat
  // session. The backend is stateless per request, so this prevents stale
  // frontend context from making the UI feel like one long-running session.
  const [messages, setMessages] = useState<ChatMessage[]>([]);

  const append = useCallback((message: ChatMessage) => {
    setMessages((prev) => [...prev, message]);
  }, []);

  const update = useCallback((id: string, patch: Partial<ChatMessage>) => {
    setMessages((prev) => prev.map((m) => (m.id === id ? { ...m, ...patch } : m)));
  }, []);

  const clear = useCallback(() => {
    setMessages([]);
  }, []);

  return { messages, append, update, clear };
}
