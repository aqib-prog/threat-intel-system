import { MatrixRain } from "./MatrixRain";
import { ParticleNetwork } from "./ParticleNetwork";
import { ScanlineOverlay } from "./ScanlineOverlay";

interface BackgroundStackProps {
  matrix?: boolean;
  particles?: boolean;
  scanlines?: boolean;
}

export function BackgroundStack({
  matrix = true,
  particles = true,
  scanlines = true,
}: BackgroundStackProps) {
  return (
    <div className="pointer-events-none fixed inset-0 z-0 bg-void">
      <div
        className="absolute inset-0"
        style={{
          background:
            "radial-gradient(ellipse 80% 60% at 50% -10%, rgba(124,58,237,0.14), transparent), radial-gradient(ellipse 60% 50% at 100% 100%, rgba(0,245,255,0.08), transparent)",
        }}
      />
      {matrix && <MatrixRain opacity={0.1} />}
      {particles && <ParticleNetwork />}
      {scanlines && <ScanlineOverlay />}
    </div>
  );
}
