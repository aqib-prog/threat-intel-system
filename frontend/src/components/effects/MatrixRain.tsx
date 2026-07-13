import { useEffect, useRef } from "react";
import { useReducedMotion } from "../../hooks/useReducedMotion";

const CHARS = "アイウエオカキクケコサシスセソ01アHYPERSCAN$#T1078TA0006>_";
const FONT_SIZE = 15;

export function MatrixRain({ opacity = 0.12 }: { opacity?: number }) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const reducedMotion = useReducedMotion();

  useEffect(() => {
    if (reducedMotion) return;
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    let width = 0;
    let height = 0;
    let drops: number[] = [];
    let frameId = 0;
    let lastTime = 0;

    const resize = () => {
      width = canvas.clientWidth;
      height = canvas.clientHeight;
      const dpr = Math.min(window.devicePixelRatio || 1, 1.5);
      canvas.width = width * dpr;
      canvas.height = height * dpr;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      const columns = Math.floor(width / FONT_SIZE);
      drops = Array.from({ length: columns }, () => Math.random() * -height);
    };

    const draw = (time: number) => {
      if (time - lastTime > 55) {
        lastTime = time;
        ctx.fillStyle = "rgba(5, 5, 8, 0.15)";
        ctx.fillRect(0, 0, width, height);
        ctx.font = `${FONT_SIZE}px "JetBrains Mono", monospace`;
        for (let i = 0; i < drops.length; i++) {
          const char = CHARS[Math.floor(Math.random() * CHARS.length)];
          const x = i * FONT_SIZE;
          const y = drops[i];
          ctx.fillStyle = "rgba(0, 255, 136, 0.75)";
          ctx.fillText(char, x, y);
          if (y > height && Math.random() > 0.975) {
            drops[i] = 0;
          } else {
            drops[i] += FONT_SIZE;
          }
        }
      }
      frameId = requestAnimationFrame(draw);
    };

    resize();
    frameId = requestAnimationFrame(draw);
    window.addEventListener("resize", resize);

    return () => {
      cancelAnimationFrame(frameId);
      window.removeEventListener("resize", resize);
    };
  }, [reducedMotion]);

  if (reducedMotion) return null;

  return (
    <canvas
      ref={canvasRef}
      className="absolute inset-0 h-full w-full"
      style={{ opacity }}
      aria-hidden="true"
    />
  );
}
