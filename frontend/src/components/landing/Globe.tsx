import { Suspense, useMemo, useRef } from "react";
import { Canvas, useFrame } from "@react-three/fiber";
import { Line } from "@react-three/drei";
import * as THREE from "three";
import { ATTACK_ROUTES, THREAT_HUBS, latLonToVector3 } from "../../lib/geo";
import { useReducedMotion } from "../../hooks/useReducedMotion";

const RADIUS = 1.7;

function buildArc(start: THREE.Vector3, end: THREE.Vector3): THREE.Vector3[] {
  const mid = start.clone().add(end).multiplyScalar(0.5);
  const liftFactor = 1 + start.distanceTo(end) / (RADIUS * 3);
  mid.normalize().multiplyScalar(RADIUS * liftFactor);
  const curve = new THREE.QuadraticBezierCurve3(start, mid, end);
  return curve.getPoints(48);
}

function WireGlobe() {
  const groupRef = useRef<THREE.Group>(null);
  const reducedMotion = useReducedMotion();

  useFrame((_, delta) => {
    if (groupRef.current && !reducedMotion) {
      groupRef.current.rotation.y += delta * 0.06;
    }
  });

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
      <mesh>
        <sphereGeometry args={[RADIUS * 0.985, 48, 48]} />
        <meshBasicMaterial color="#050810" transparent opacity={0.9} />
      </mesh>

      {gridLines.map((pts, i) => (
        <Line key={i} points={pts} color="#00f5ff" transparent opacity={0.14} lineWidth={1} />
      ))}

      {hubPositions.map((p, i) => (
        <mesh key={i} position={p}>
          <sphereGeometry args={[0.018, 8, 8]} />
          <meshBasicMaterial color="#00ff88" />
        </mesh>
      ))}

      {arcs.map((pts, i) => (
        <Line
          key={i}
          points={pts}
          color="#ff3366"
          transparent
          opacity={0.65}
          lineWidth={1.5}
        />
      ))}
    </group>
  );
}

export function Globe() {
  return (
    <div className="h-full w-full">
      <Canvas
        dpr={[1, 1.5]}
        camera={{ position: [0, 0, 4.4], fov: 42 }}
        gl={{ antialias: true, alpha: true }}
      >
        <Suspense fallback={null}>
          <ambientLight intensity={1.2} />
          <WireGlobe />
        </Suspense>
      </Canvas>
    </div>
  );
}
