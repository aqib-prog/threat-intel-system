export function StatCardSkeleton() {
  return (
    <div
      className="holo-card corner-brackets relative overflow-hidden rounded-xl px-5 py-6 sm:px-7 sm:py-8"
      aria-hidden="true"
    >
      <div className="h-[clamp(1.5rem,4.5vw,2.75rem)] w-24 animate-pulse rounded bg-border-dim" />
      <div className="mt-3 h-2.5 w-28 animate-pulse rounded bg-border-dim/70" />
    </div>
  );
}
