import { useEffect, useMemo, useRef, useState } from "react";
import {
  forceSimulation,
  forceLink,
  forceManyBody,
  forceCollide,
  type Simulation,
  type SimulationNodeDatum,
} from "d3-force";
import { drag as d3drag } from "d3-drag";
import { select } from "d3-selection";
import { zoom as d3zoom, zoomIdentity } from "d3-zoom";
import { clsx } from "clsx";
import { Graph as GraphIcon } from "@phosphor-icons/react";
import { MAX_RELEVANCE_SCORE, type NodeSource } from "../../lib/types";
import { ACCENT_HEX, accentForNodeType, hexToRgba, humanizeLabel } from "../../lib/colorTokens";
import { iconForNodeType } from "../../lib/nodeIcons";
import { useReducedMotion } from "../../hooks/useReducedMotion";

interface GraphNode extends SimulationNodeDatum {
  id: string;
  name: string;
  type: string;
  externalId: string | null;
  score: number;
  isHub: boolean;
}

interface GraphLink {
  source: string | GraphNode;
  target: string | GraphNode;
  strength: number;
}

const HUB_ID = "__query__";
const MIN_RADIUS = 12;
const MAX_RADIUS = 24;
const HUB_RADIUS = 22;

function nodeRadius(n: GraphNode): number {
  if (n.isHub) return HUB_RADIUS;
  const pct = Math.min(1, Math.max(0, n.score / MAX_RELEVANCE_SCORE));
  return MIN_RADIUS + pct * (MAX_RADIUS - MIN_RADIUS);
}

function buildGraph(nodes: NodeSource[]): { graphNodes: GraphNode[]; graphLinks: GraphLink[] } {
  const hub: GraphNode = {
    id: HUB_ID,
    name: "SOURCES",
    type: "hub",
    externalId: null,
    score: MAX_RELEVANCE_SCORE,
    isHub: true,
  };
  const rest: GraphNode[] = nodes.map((n, i) => ({
    id: `${n.external_id ?? n.name}-${i}`,
    name: n.name,
    type: n.node_type,
    externalId: n.external_id,
    score: n.relevance_score ?? 0,
    isHub: false,
  }));
  const links: GraphLink[] = rest.map((n) => ({
    source: HUB_ID,
    target: n.id,
    strength: Math.min(1, Math.max(0, n.score / MAX_RELEVANCE_SCORE)),
  }));
  return { graphNodes: [hub, ...rest], graphLinks: links };
}

interface HoverInfo {
  node: NodeSource;
  x: number;
  y: number;
}

export function SourceGraph({ nodes }: { nodes: NodeSource[] }) {
  const containerRef = useRef<HTMLDivElement>(null);
  const svgRef = useRef<SVGSVGElement>(null);
  const zoomLayerRef = useRef<SVGGElement>(null);
  const nodeElRefs = useRef<Map<string, SVGGElement>>(new Map());
  const linkElRefs = useRef<Map<number, SVGLineElement>>(new Map());
  const simulationRef = useRef<Simulation<GraphNode, undefined> | null>(null);
  const reducedMotion = useReducedMotion();
  const [size, setSize] = useState({ width: 480, height: 320 });
  const [hover, setHover] = useState<HoverInfo | null>(null);

  const nodesByKey = useMemo(() => {
    const map = new Map<string, NodeSource>();
    nodes.forEach((n, i) => map.set(`${n.external_id ?? n.name}-${i}`, n));
    return map;
  }, [nodes]);

  const { graphNodes, graphLinks } = useMemo(() => buildGraph(nodes), [nodes]);

  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;
    const update = () => setSize({ width: el.clientWidth, height: el.clientHeight });
    update();
    const observer = new ResizeObserver(update);
    observer.observe(el);
    return () => observer.disconnect();
  }, []);

  useEffect(() => {
    const { width, height } = size;
    if (width === 0 || height === 0) return;

    const hub = graphNodes.find((n) => n.isHub);
    if (hub) {
      hub.x = width / 2;
      hub.y = height / 2;
      hub.fx = width / 2;
      hub.fy = height / 2;
    }
    graphNodes.forEach((n, i) => {
      if (n.isHub || n.x !== undefined) return;
      const count = Math.max(1, graphNodes.length - 1);
      const angle = ((i - 1) / count) * Math.PI * 2;
      n.x = width / 2 + Math.cos(angle) * Math.min(width, height) * 0.28;
      n.y = height / 2 + Math.sin(angle) * Math.min(width, height) * 0.28;
    });

    const ticked = () => {
      linkElRefs.current.forEach((el, i) => {
        const link = graphLinks[i];
        const s = link.source as GraphNode;
        const t = link.target as GraphNode;
        if (s.x === undefined || t.x === undefined) return;
        el.setAttribute("x1", String(s.x));
        el.setAttribute("y1", String(s.y));
        el.setAttribute("x2", String(t.x));
        el.setAttribute("y2", String(t.y));
      });
      nodeElRefs.current.forEach((el, id) => {
        const n = graphNodes.find((gn) => gn.id === id);
        if (n && n.x !== undefined) el.setAttribute("transform", `translate(${n.x},${n.y})`);
      });
    };

    const simulation = forceSimulation<GraphNode>(graphNodes)
      .force(
        "link",
        forceLink<GraphNode, GraphLink>(graphLinks)
          .id((d) => d.id)
          .distance((d) => 55 + (1 - d.strength) * 95)
          .strength(0.85)
      )
      .force("charge", forceManyBody().strength(-170))
      .force(
        "collide",
        forceCollide<GraphNode>().radius((d) => nodeRadius(d) + 16)
      )
      .alpha(1)
      .on("tick", ticked);

    if (reducedMotion) {
      simulation.stop();
      for (let i = 0; i < 300; i++) simulation.tick();
      ticked();
    }

    simulationRef.current = simulation;

    const dragBehavior = d3drag<SVGGElement, GraphNode>()
      .on("start", (event) => {
        const n = event.subject;
        if (!n) return;
        if (!event.active) simulation.alphaTarget(0.25).restart();
        n.fx = n.x;
        n.fy = n.y;
      })
      .on("drag", (event) => {
        const n = event.subject;
        if (!n) return;
        n.fx = event.x;
        n.fy = event.y;
      })
      .on("end", (event) => {
        const n = event.subject;
        if (!event.active) simulation.alphaTarget(0);
        if (n && !n.isHub) {
          n.fx = null;
          n.fy = null;
        }
      });

    graphNodes.forEach((n) => {
      const el = nodeElRefs.current.get(n.id);
      if (el) select(el).datum(n).call(dragBehavior);
    });

    const zoomBehavior = d3zoom<SVGSVGElement, unknown>()
      .scaleExtent([0.6, 2.5])
      .on("zoom", (event) => {
        zoomLayerRef.current?.setAttribute("transform", event.transform.toString());
      });

    if (svgRef.current) {
      select(svgRef.current).call(zoomBehavior).call(zoomBehavior.transform, zoomIdentity);
    }

    return () => {
      simulation.stop();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [graphNodes, graphLinks, size.width, size.height, reducedMotion]);

  if (nodes.length === 0) return null;

  return (
    <div ref={containerRef} className="relative h-[280px] w-full overflow-visible rounded-lg border border-border-glow bg-void-panel/60">
      <svg
        ref={svgRef}
        viewBox={`0 0 ${size.width} ${size.height}`}
        className="h-full w-full touch-none select-none"
      >
        <g ref={zoomLayerRef}>
          <g>
            {graphLinks.map((link, i) => (
              <line
                key={i}
                ref={(el) => {
                  if (el) linkElRefs.current.set(i, el);
                  else linkElRefs.current.delete(i);
                }}
                stroke={ACCENT_HEX.cyan}
                strokeOpacity={0.14 + link.strength * 0.28}
                strokeWidth={1 + link.strength * 1.5}
              />
            ))}
          </g>
          <g>
            {graphNodes.map((n) => {
              const accentColor = n.isHub ? "cyan" : accentForNodeType(n.type);
              const hex = ACCENT_HEX[accentColor];
              const Icon = n.isHub ? GraphIcon : iconForNodeType(n.type);
              const r = nodeRadius(n);
              const source = nodesByKey.get(n.id);
              return (
                <g
                  key={n.id}
                  ref={(el) => {
                    if (el) nodeElRefs.current.set(n.id, el);
                    else nodeElRefs.current.delete(n.id);
                  }}
                  className="cursor-grab outline-none active:cursor-grabbing"
                  tabIndex={n.isHub ? -1 : 0}
                  role={n.isHub ? undefined : "button"}
                  aria-label={n.isHub ? undefined : `${n.name}, ${humanizeLabel(n.type)}`}
                  onMouseEnter={(e) => {
                    if (n.isHub || !source) return;
                    const rect = containerRef.current?.getBoundingClientRect();
                    if (!rect) return;
                    setHover({ node: source, x: e.clientX - rect.left, y: e.clientY - rect.top });
                  }}
                  onMouseMove={(e) => {
                    if (n.isHub || !source) return;
                    const rect = containerRef.current?.getBoundingClientRect();
                    if (!rect) return;
                    setHover({ node: source, x: e.clientX - rect.left, y: e.clientY - rect.top });
                  }}
                  onMouseLeave={() => setHover(null)}
                  onFocus={() => {
                    if (n.isHub || !source || n.x === undefined || n.y === undefined) return;
                    setHover({ node: source, x: n.x, y: n.y });
                  }}
                  onBlur={() => setHover(null)}
                >
                  <circle
                    r={r}
                    fill={hexToRgba(hex, n.isHub ? 0.12 : 0.16)}
                    stroke={hex}
                    strokeWidth={n.isHub ? 1.75 : 1.25}
                  />
                  <foreignObject x={-8} y={-8} width={16} height={16} className="pointer-events-none overflow-visible">
                    <Icon size={16} weight="bold" color={hex} />
                  </foreignObject>
                  {!n.isHub && (
                    <text
                      y={r + 13}
                      textAnchor="middle"
                      className="fill-text-mid font-mono"
                      style={{ fontSize: "8px" }}
                    >
                      {n.externalId ?? n.name.slice(0, 12)}
                    </text>
                  )}
                </g>
              );
            })}
          </g>
        </g>
      </svg>

      {hover && (
        <div
          className={clsx(
            "pointer-events-none absolute z-10 max-w-[min(260px,calc(100%-24px))] -translate-x-1/2 rounded-lg border border-border-glow bg-void-raised px-3 py-2 font-mono text-[11px] text-white shadow-[0_0_28px_-12px_rgba(0,245,255,0.75)]",
            hover.y < 96 ? "translate-y-3" : "-translate-y-[calc(100%+14px)]"
          )}
          style={{ left: `clamp(130px, ${hover.x}px, calc(100% - 130px))`, top: hover.y }}
        >
          <p className="break-words font-semibold">{hover.node.name}</p>
          <p className="text-text-mid">{humanizeLabel(hover.node.node_type)}</p>
          {hover.node.relevance_score !== null && (
            <p className="text-text-dim">
              {Math.round(Math.min(1, Math.max(0, (hover.node.relevance_score ?? 0) / MAX_RELEVANCE_SCORE)) * 100)}% relevance
            </p>
          )}
        </div>
      )}

    </div>
  );
}
