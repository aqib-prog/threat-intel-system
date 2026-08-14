import { Suspense, useMemo, useRef, useState } from "react";
import { AnimatePresence, motion } from "framer-motion";
import { Canvas, useFrame } from "@react-three/fiber";
import { Line } from "@react-three/drei";
import * as THREE from "three";
import { ATTACK_ROUTES, REGION_INTEL, THREAT_HUBS, latLonToVector3 } from "../../lib/geo";
import { useReducedMotion } from "../../hooks/useReducedMotion";

const RADIUS = 1.7;

function buildArc(start: THREE.Vector3, end: THREE.Vector3): THREE.Vector3[] {
  const mid = start.clone().add(end).multiplyScalar(0.5);
  const liftFactor = 1 + start.distanceTo(end) / (RADIUS * 3);
  mid.normalize().multiplyScalar(RADIUS * liftFactor);
  const curve = new THREE.QuadraticBezierCurve3(start, mid, end);
  return curve.getPoints(48);
}

/**
 * Expanding rings on the inspected city.
 *
 * Driven by useFrame rather than CSS, because this lives inside the WebGL
 * scene and has to stay locked to a point on a rotating sphere. Two rings on
 * opposite phases keep the pulse continuous instead of blinking.
 */
function HubPulse() {
  const ringA = useRef<THREE.Mesh>(null);
  const ringB = useRef<THREE.Mesh>(null);
  const time = useRef(0);

  useFrame((_, delta) => {
    time.current += delta;
    for (const [index, ring] of [ringA, ringB].entries()) {
      if (!ring.current) continue;
      const phase = (time.current / 1.9 + index * 0.5) % 1;
      const scale = 0.4 + phase * 2.6;
      ring.current.scale.setScalar(scale);
      const material = ring.current.material as THREE.MeshBasicMaterial;
      // Fade as it expands so each ring dissolves rather than popping.
      material.opacity = 0.5 * (1 - phase);
    }
  });

  return (
    <>
      {[ringA, ringB].map((ref, index) => (
        <mesh key={index} ref={ref}>
          <sphereGeometry args={[0.045, 16, 16]} />
          <meshBasicMaterial color="#00ff88" transparent opacity={0.5} depthWrite={false} />
        </mesh>
      ))}
    </>
  );
}


/**
 * The globe surface itself, as a shader.
 *
 * Hovering does not just highlight a marker - it physically deforms the sphere:
 * vertices near the cursor are pushed along their normals, so the surface
 * blisters outward and settles back as you move away. Doing this on the GPU is
 * what makes it viable; displacing 16k vertices per frame from JavaScript would
 * not hold a frame rate.
 *
 * The glitch is deliberately tied to the SAME influence value that drives the
 * bulge, so the corruption only appears where the surface is being disturbed -
 * a scanline sweeping the whole globe would read as decoration, this reads as
 * the probe doing something.
 */
const bulgeVertex = /* glsl */ `
  uniform vec3 uHover;
  uniform float uStrength;
  uniform float uTime;
  varying float vInfluence;
  varying vec3 vNormalW;

  void main() {
    vec3 dir = normalize(position);
    // Angular distance from the probe point, so the falloff is even across the
    // sphere rather than distorted near the poles.
    float angle = acos(clamp(dot(dir, normalize(uHover)), -1.0, 1.0));
    // Tighter radius and an eased falloff: the previous wide, linear influence
    // lifted a broad flat slab. Raising it to a power rounds the shoulders so it
    // reads as a blister on the surface.
    float falloff = smoothstep(0.62, 0.0, angle);
    float influence = pow(falloff, 1.7) * uStrength;

    // A little ripple travelling out from the centre of the bulge.
    float ripple = sin(angle * 22.0 - uTime * 5.0) * 0.035 * influence;

    vec3 displaced = position + normal * (influence * 0.22 + ripple);
    vInfluence = influence;
    vNormalW = normal;
    gl_Position = projectionMatrix * modelViewMatrix * vec4(displaced, 1.0);
  }
`;

const bulgeFragment = /* glsl */ `
  uniform float uTime;
  varying float vInfluence;
  varying vec3 vNormalW;

  // Cheap hash for the glitch bands - no texture lookup needed.
  float hash(float n) { return fract(sin(n) * 43758.5453123); }

  void main() {
    vec3 base = vec3(0.016, 0.026, 0.055);
    vec3 hot = vec3(0.0, 1.0, 0.53);
    vec3 edge = vec3(0.0, 0.96, 1.0);

    // Horizontal tear lines that jump between discrete rows, so it reads as
    // signal corruption rather than a smooth gradient.
    float row = floor(vNormalW.y * 70.0);
    float jitter = step(0.82, hash(row + floor(uTime * 12.0)));
    float glitch = jitter * vInfluence;

    // Rim: the steep flank of the blister catches the most light.
    float rim = smoothstep(0.35, 0.95, vInfluence);

    vec3 color = base;
    color = mix(color, hot, vInfluence * 0.55);
    color = mix(color, edge, rim * 0.5 + glitch * 0.6);

    float alpha = 0.9 + vInfluence * 0.1;
    gl_FragColor = vec4(color, alpha);
  }
`;

function BulgeSphere({
  hoverPoint,
  active,
}: {
  hoverPoint: THREE.Vector3;
  active: boolean;
}) {
  const materialRef = useRef<THREE.ShaderMaterial>(null);
  const uniforms = useMemo(
    () => ({
      uHover: { value: new THREE.Vector3(0, 0, 1) },
      uStrength: { value: 0 },
      uTime: { value: 0 },
    }),
    []
  );

  useFrame((_, delta) => {
    const material = materialRef.current;
    if (!material) return;
    material.uniforms.uTime.value += delta;
    // Ease the probe point and its strength rather than snapping: the surface
    // should feel like it is being pushed, not teleported.
    material.uniforms.uHover.value.lerp(hoverPoint, Math.min(1, delta * 9));
    const target = active ? 1 : 0;
    material.uniforms.uStrength.value +=
      (target - material.uniforms.uStrength.value) * Math.min(1, delta * 6);
  });

  return (
    <mesh>
      {/* Dense enough that the displacement reads as a smooth blister; a
          48-segment sphere shows facets under this much deformation. */}
      <sphereGeometry args={[RADIUS * 0.985, 160, 160]} />
      <shaderMaterial
        ref={materialRef}
        uniforms={uniforms}
        vertexShader={bulgeVertex}
        fragmentShader={bulgeFragment}
        transparent
      />
    </mesh>
  );
}

function nearestHub(point: THREE.Vector3): number {
  let best = 0;
  let bestDistance = Infinity;
  THREAT_HUBS.forEach((hub, index) => {
    const distance = latLonToVector3(hub.lat, hub.lon, RADIUS).distanceTo(point);
    if (distance < bestDistance) {
      bestDistance = distance;
      best = index;
    }
  });
  return best;
}

function WireGlobe({ onHover }: { onHover: (index: number | null) => void }) {
  const groupRef = useRef<THREE.Group>(null);
  const reducedMotion = useReducedMotion();
  // Which region is being inspected. Drives the hub, its label, and which
  // attack routes stay lit.
  const [hovered, setHovered] = useState<number | null>(null);
  // Where the pointer is touching the surface, in the globe's local space.
  const [probe, setProbe] = useState(() => new THREE.Vector3(0, 0, RADIUS));
  const [probeActive, setProbeActive] = useState(false);

  useFrame((_, delta) => {
    if (!groupRef.current || reducedMotion) return;
    // Ease to a stop while a region is held, and back up to speed on release -
    // a hard stop reads as a bug, a glide reads as the globe yielding to you.
    const target = hovered === null ? 0.06 : 0.004;
    spinRef.current += (target - spinRef.current) * Math.min(1, delta * 4);
    groupRef.current.rotation.y += delta * spinRef.current;
  });

  const spinRef = useRef(0.06);

  const hubPositions = useMemo(
    () => THREAT_HUBS.map((c) => latLonToVector3(c.lat, c.lon, RADIUS)),
    []
  );

  const arcs = useMemo(
    () =>
      ATTACK_ROUTES.map(([a, b]) => buildArc(hubPositions[a], hubPositions[b])),
    [hubPositions]
  );

  const gridLines = useMemo(() => {
    const lines: THREE.Vector3[][] = [];
    for (let i = -60; i <= 60; i += 20) {
      const pts: THREE.Vector3[] = [];
      for (let lon = -180; lon <= 180; lon += 6) {
        pts.push(latLonToVector3(i, lon, RADIUS));
      }
      lines.push(pts);
    }
    for (let lon = -180; lon < 180; lon += 20) {
      const pts: THREE.Vector3[] = [];
      for (let lat = -90; lat <= 90; lat += 6) {
        pts.push(latLonToVector3(lat, lon, RADIUS));
      }
      lines.push(pts);
    }
    return lines;
  }, []);

  return (
    <group ref={groupRef}>
      <BulgeSphere hoverPoint={probe} active={probeActive} />

      {/* Invisible collider slightly outside the surface: it catches the
          pointer everywhere, so the bulge follows the cursor across the whole
          globe instead of only over the city markers. */}
      <mesh
        onPointerMove={(event) => {
          event.stopPropagation();
          // Into the group's local space, so the probe stays put on the
          // surface while the globe keeps rotating underneath it.
          const local = event.point.clone();
          groupRef.current?.worldToLocal(local);
          setProbe(local.normalize().multiplyScalar(RADIUS));
          setProbeActive(true);
          onHover(nearestHub(local));
        }}
        onPointerOut={() => {
          setProbeActive(false);
          onHover(null);
        }}
      >
        <sphereGeometry args={[RADIUS * 1.02, 32, 32]} />
        <meshBasicMaterial transparent opacity={0} depthWrite={false} side={THREE.BackSide} />
      </mesh>

      {gridLines.map((pts, i) => (
        <Line key={i} points={pts} color="#00f5ff" transparent opacity={0.14} lineWidth={1} />
      ))}

      {hubPositions.map((p, i) => {
        const isActive = hovered === i;
        // A city at the far end of a lit route is a peer, not background: it
        // stays bright so the reader can see WHERE the traffic goes.
        const isPeer =
          hovered !== null &&
          !isActive &&
          ATTACK_ROUTES.some(
            ([from, to]) =>
              (from === hovered && to === i) || (to === hovered && from === i)
          );
        const isMuted = hovered !== null && !isActive && !isPeer;
        return (
          <group key={i} position={p}>
            {/* Generous invisible hit area: an 0.018-radius sphere on a
                rotating globe is far too small to reliably hover. */}
            <mesh
              onPointerOver={(event) => {
                event.stopPropagation();
                setHovered(i);
                onHover(i);
                setProbe(p.clone());
                setProbeActive(true);
              }}
              onPointerOut={() => {
                setHovered(null);
                onHover(null);
              }}
            >
              <sphereGeometry args={[0.075, 8, 8]} />
              <meshBasicMaterial transparent opacity={0} depthWrite={false} />
            </mesh>

            {/* Halo, only for the region under the cursor. */}
            {isActive && (
              <mesh>
                <sphereGeometry args={[0.055, 16, 16]} />
                <meshBasicMaterial color="#00ff88" transparent opacity={0.22} depthWrite={false} />
              </mesh>
            )}

            <mesh scale={isActive ? 1.9 : isPeer ? 1.35 : 1}>
              <sphereGeometry args={[0.018, 8, 8]} />
              <meshBasicMaterial
                color={isActive ? "#7cffb2" : isPeer ? "#00f5ff" : "#00ff88"}
                transparent
                opacity={isMuted ? 0.25 : 1}
              />
            </mesh>

            {isActive && <HubPulse />}

          </group>
        );
      })}

      {arcs.map((pts, i) => {
        // Only the routes that actually touch the hovered city stay lit, so
        // hovering answers "what connects here?" rather than just glowing.
        const [from, to] = ATTACK_ROUTES[i];
        const connected = hovered !== null && (from === hovered || to === hovered);
        const muted = hovered !== null && !connected;
        return (
          <Line
            key={i}
            points={pts}
            color={connected ? "#ff6b8f" : "#ff3366"}
            transparent
            opacity={muted ? 0.12 : connected ? 0.95 : 0.65}
            lineWidth={connected ? 2.4 : 1.5}
          />
        );
      })}
    </group>
  );
}

export function Globe() {
  const [hovered, setHovered] = useState<number | null>(null);
  // Where the pointer is touching the surface, in the globe's local space.
  const [probe, setProbe] = useState(() => new THREE.Vector3(0, 0, RADIUS));
  const [probeActive, setProbeActive] = useState(false);

  // Route counts live here, beside the panel that renders them.
  const routeCounts = useMemo(() => {
    const counts = new Array(THREAT_HUBS.length).fill(0);
    for (const [from, to] of ATTACK_ROUTES) {
      counts[from] += 1;
      counts[to] += 1;
    }
    return counts;
  }, []);

  const peers = useMemo(() => {
    if (hovered === null) return [];
    return ATTACK_ROUTES.filter(([a, b]) => a === hovered || b === hovered).map(
      ([a, b]) => THREAT_HUBS[a === hovered ? b : a].name
    );
  }, [hovered]);

  return (
    <div className="relative h-full w-full">
      <Canvas
        dpr={[1, 1.5]}
        // Distance is headroom for the bulge. The globe previously filled almost
        // the entire canvas, so a blister anywhere on the limb was cut off by the
        // canvas edge - there was simply nowhere for the deformed surface to go.
        // Backing the camera off leaves margin on all four sides.
        camera={{ position: [0, 0, 6.4], fov: 42 }}
        gl={{ antialias: true, alpha: true }}
      >
        <Suspense fallback={null}>
          <ambientLight intensity={1.2} />
          <WireGlobe onHover={setHovered} />
        </Suspense>
      </Canvas>

      {/* HUD panel, rendered OUTSIDE the canvas.
          Drei's <Html> lives inside the canvas container, so a label attached to
          a node near the edge was clipped by it. A fixed corner readout is also
          simply easier to read than text that swims around a rotating sphere. */}
      <AnimatePresence>
        {hovered !== null && (
          <motion.div
            initial={{ opacity: 0, x: -10 }}
            animate={{ opacity: 1, x: 0 }}
            exit={{ opacity: 0, x: -6 }}
            transition={{ duration: 0.22, ease: [0.16, 1, 0.3, 1] }}
            className="pointer-events-none absolute bottom-4 left-4 z-20 w-64 rounded-xl border border-green/30 px-3.5 py-3 font-mono"
            style={{
              background:
                "linear-gradient(145deg, rgba(0,255,136,0.12) 0%, rgba(5,8,16,0.96) 55%)",
              boxShadow:
                "inset 0 1px 0 rgba(255,255,255,0.14), 0 20px 44px -24px rgba(0,255,136,0.8)",
            }}
          >
            <p className="flex items-center gap-1.5 text-[9px] uppercase tracking-[0.25em] text-green">
              <span className="inline-block h-1.5 w-1.5 rounded-full bg-green motion-safe:animate-pulse" />
              Node active
            </p>
            <p className="mt-1.5 text-sm font-semibold text-white">
              {THREAT_HUBS[hovered].name}
            </p>
            <p className="mt-0.5 text-[10px] text-text-dim">
              {Math.abs(THREAT_HUBS[hovered].lat).toFixed(1)}°
              {THREAT_HUBS[hovered].lat >= 0 ? "N" : "S"}{" "}
              {Math.abs(THREAT_HUBS[hovered].lon).toFixed(1)}°
              {THREAT_HUBS[hovered].lon >= 0 ? "E" : "W"}
            </p>

            <div className="mt-2.5 space-y-1.5 border-t border-border-dim pt-2">
              <div>
                <p className="text-[9px] uppercase tracking-[0.2em] text-text-dim">
                  Attributed actors
                </p>
                <p className="mt-0.5 text-[11px] text-red">
                  {REGION_INTEL[THREAT_HUBS[hovered].name]?.actors ?? "Unattributed"}
                </p>
              </div>

              <div className="flex items-center justify-between gap-2">
                <div className="min-w-0">
                  <p className="text-[9px] uppercase tracking-[0.2em] text-text-dim">
                    Dominant tactic
                  </p>
                  <p className="mt-0.5 truncate text-[11px] text-amber">
                    {REGION_INTEL[THREAT_HUBS[hovered].name]?.tactic ?? "—"}
                  </p>
                </div>
                <span className="shrink-0 rounded border border-amber/30 bg-amber/10 px-1.5 py-0.5 text-[10px] text-amber">
                  {REGION_INTEL[THREAT_HUBS[hovered].name]?.technique ?? "—"}
                </span>
              </div>

              <div>
                <p className="text-[9px] uppercase tracking-[0.2em] text-text-dim">
                  {routeCounts[hovered]} active {routeCounts[hovered] === 1 ? "route" : "routes"}
                </p>
                <p className="mt-0.5 text-[10px] leading-relaxed text-cyan">
                  {peers.slice(0, 3).join(" · ")}
                  {peers.length > 3 ? ` +${peers.length - 3}` : ""}
                </p>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
