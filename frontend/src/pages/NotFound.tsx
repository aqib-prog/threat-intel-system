import { Link } from "react-router-dom";
import { BackgroundStack } from "../components/effects/BackgroundStack";

export function NotFound() {
  return (
    <div className="relative flex min-h-dvh flex-col items-center justify-center gap-4 bg-void px-6 text-center">
      <BackgroundStack particles={false} />
      <p className="relative z-10 font-mono text-sm uppercase tracking-[0.3em] text-red">
        404 · NODE NOT FOUND
      </p>
      <h1 className="relative z-10 font-display text-3xl font-semibold text-white">
        This route isn't in the graph.
      </h1>
      <Link
        to="/"
        className="relative z-10 mt-2 rounded-full border border-cyan/40 px-5 py-2 font-mono text-xs tracking-widest text-cyan transition-colors hover:bg-cyan/10"
      >
        RETURN TO BASE
      </Link>
    </div>
  );
}
