interface ScanlineOverlayProps {
  animated?: boolean;
}

export function ScanlineOverlay({ animated = true }: ScanlineOverlayProps) {
  return (
    <div className="pointer-events-none absolute inset-0 z-40 overflow-hidden" aria-hidden="true">
      <div
        className="absolute inset-0"
        style={{
          backgroundImage:
            "repeating-linear-gradient(to bottom, rgba(255,255,255,0.4) 0px, rgba(255,255,255,0.4) 1px, transparent 1px, transparent 3px)",
          opacity: 0.05,
          mixBlendMode: "overlay",
        }}
      />
      {animated && (
        <div
          className="absolute inset-x-0 h-24 motion-safe:animate-scan"
          style={{
            background:
              "linear-gradient(to bottom, transparent, rgba(0,245,255,0.035), transparent)",
          }}
        />
      )}
      <div
        className="absolute inset-0"
        style={{
          boxShadow: "inset 0 0 140px rgba(0,0,0,0.75)",
        }}
      />
    </div>
  );
}
