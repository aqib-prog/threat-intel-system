import { useEffect, useRef, useState } from "react";
import { checkHealth } from "../lib/api";
import type { ConnectionState } from "../lib/types";

const POLL_MS = 15000;

export function useConnectionStatus(): ConnectionState {
  const [state, setState] = useState<ConnectionState>("checking");
  const mounted = useRef(true);

  useEffect(() => {
    mounted.current = true;
    const poll = async () => {
      const ok = await checkHealth();
      if (mounted.current) setState(ok ? "online" : "offline");
    };
    poll();
    const id = setInterval(poll, POLL_MS);
    return () => {
      mounted.current = false;
      clearInterval(id);
    };
  }, []);

  return state;
}
