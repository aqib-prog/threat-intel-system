import { useEffect, useRef } from "react";
import { useReducedMotion } from "../../hooks/useReducedMotion";

/**
 * Ambient backdrop for the auth screens.
 *
 * A constellation that slowly rewires itself: nodes drift, and an edge is drawn
 * only while two nodes are close enough. It reads as the knowledge graph the
 * product is built on, still forming - the visual argument for "you are at the
 * edge of the system, not inside it yet".
 *
 * Sized from the VIEWPORT, never from clientHeight. That is not a style choice:
 * an earlier canvas here sized itself from layout and produced a backbuffer ten
 * times too tall, which alone made the page unusable.
 */

const NODE_COUNT = 46;
const LINK_DISTANCE = 168;

interface Node {
  x: number;
  y: number;
  vx: number;
  vy: number;
  r: number;
}

export function AuthBackdrop() {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const reduced = useReducedMotion();

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    let width = 0;
    let height = 0;
    let nodes: Node[] = [];
    let frame = 0;

    const resize = () => {
      const dpr = Math.min(window.devicePixelRatio || 1, 2);
      width = Math.max(1, window.innerWidth);
      height = Math.max(1, window.innerHeight);
      canvas.width = width * dpr;
      canvas.height = height * dpr;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    };

    const seed = () => {
      nodes = Array.from({ length: NODE_COUNT }, () => ({
        x: Math.random() * width,
        y: Math.random() * height,
        vx: (Math.random() - 0.5) * 0.16,
        vy: (Math.random() - 0.5) * 0.16,
        r: 1 + Math.random() * 1.7,
      }));
    };

    const draw = () => {
      ctx.clearRect(0, 0, width, height);

      for (let i = 0; i < nodes.length; i += 1) {
        for (let j = i + 1; j < nodes.length; j += 1) {
          const a = nodes[i];
          const b = nodes[j];
          const dx = a.x - b.x;
          const dy = a.y - b.y;
          const distance = Math.hypot(dx, dy);
          if (distance >= LINK_DISTANCE) continue;
          // Fade with distance so links resolve and dissolve rather than blink.
          const strength = 1 - distance / LINK_DISTANCE;
          ctx.strokeStyle = `rgba(0, 245, 255, ${0.16 * strength})`;
          ctx.lineWidth = 0.7;
          ctx.beginPath();
          ctx.moveTo(a.x, a.y);
          ctx.lineTo(b.x, b.y);
          ctx.stroke();
        }
      }

      for (const node of nodes) {
        ctx.beginPath();
        ctx.arc(node.x, node.y, node.r, 0, Math.PI * 2);
        ctx.fillStyle = "rgba(0, 245, 255, 0.42)";
        ctx.fill();
      }
    };

    const step = () => {
      for (const node of nodes) {
        node.x += node.vx;
        node.y += node.vy;
        if (node.x < 0 || node.x > width) node.vx *= -1;
        if (node.y < 0 || node.y > height) node.vy *= -1;
      }
      draw();
      frame = requestAnimationFrame(step);
    };

    resize();
    seed();
    if (reduced) {
      draw();
    } else {
      frame = requestAnimationFrame(step);
    }

    const onResize = () => {
      resize();
      seed();
      if (reduced) draw();
    };
    window.addEventListener("resize", onResize);
    return () => {
      cancelAnimationFrame(frame);
      window.removeEventListener("resize", onResize);
    };
  }, [reduced]);

  return (
    <div aria-hidden="true" className="pointer-events-none fixed inset-0 z-0 overflow-hidden bg-void">
      <canvas ref={canvasRef} className="absolute inset-0 h-full w-full opacity-70" />
      <div
        className="absolute inset-0"
        style={{
          background:
            "radial-gradient(ellipse 70% 55% at 15% 0%, rgba(0,245,255,0.13), transparent 65%), radial-gradient(ellipse 60% 50% at 100% 100%, rgba(124,58,237,0.14), transparent 68%)",
        }}
      />
      {/* Vignette keeps the centre column legible over the moving graph. */}
      <div
        className="absolute inset-0"
        style={{
          background:
            "radial-gradient(ellipse 55% 60% at 50% 50%, rgba(5,5,8,0.55) 0%, rgba(5,5,8,0.82) 60%, rgba(5,5,8,0.92) 100%)",
        }}
      />
    </div>
  );
}
