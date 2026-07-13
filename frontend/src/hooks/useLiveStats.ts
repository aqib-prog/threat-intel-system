import { useEffect, useState } from "react";
import { fetchStats } from "../lib/api";
import type { StatsResponse } from "../lib/types";

interface LiveStatsState {
  stats: StatsResponse | null;
  isFallback: boolean;
  loading: boolean;
}

/** Fetches real graph counts from GET /stats. Never fabricates numbers -
 * falls back to the last-known snapshot in lib/mock.ts, clearly flagged via
 * isFallback so the UI can label it as such. */
export function useLiveStats(): LiveStatsState {
  const [state, setState] = useState<LiveStatsState>({
    stats: null,
    isFallback: false,
    loading: true,
  });

  useEffect(() => {
    let mounted = true;
    fetchStats().then(({ data, isFallback }) => {
      if (mounted) setState({ stats: data, isFallback, loading: false });
    });
    return () => {
      mounted = false;
    };
  }, []);

  return state;
}
