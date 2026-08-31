import { useMemo } from "react";
import {
  forceCenter,
  forceCollide,
  forceLink,
  forceManyBody,
  forceSimulation,
  type SimulationLinkDatum,
  type SimulationNodeDatum,
} from "d3-force";
import type { GraphEdge, GraphNode } from "../api/assets";

interface SimNode extends SimulationNodeDatum {
  id: string;
  node: GraphNode;
}

interface SimLink extends SimulationLinkDatum<SimNode> {
  edge: GraphEdge;
}

interface GraphViewProps {
  nodes: GraphNode[];
  edges: GraphEdge[];
  seedAssetId: string;
  onNodeClick?: (node: GraphNode) => void;
  width?: number;
  height?: number;
}

// No design-token/color-palette file exists in this project (see
// frontend architecture notes) -- these are plain hex values chosen for
// contrast against the white canvas, matching this component's own
// self-contained scope rather than inventing a shared palette file for
// a single consumer.
const TYPE_COLORS: Record<string, string> = {
  domain: "#0ea5e9",
  subdomain: "#38bdf8",
  ip_address: "#f97316",
  ip_range: "#fb923c",
  url: "#a855f7",
  asn: "#64748b",
  cloud_resource: "#14b8a6",
  service: "#eab308",
  tls_certificate: "#22c55e",
  api: "#ec4899",
  repository: "#8b5cf6",
};
const DEFAULT_COLOR = "#94a3b8";

function colorForType(assetType: string): string {
  return TYPE_COLORS[assetType] ?? DEFAULT_COLOR;
}

function asSimNode(value: string | number | SimNode): SimNode {
  // After forceSimulation runs, d3-force mutates every link's
  // source/target from a bare id (string) into the resolved node object
  // in place -- this narrows the type at the one point that's actually
  // true, right after layout has settled, never before.
  return value as SimNode;
}

function truncateLabel(value: string, max = 22): string {
  return value.length > max ? `${value.slice(0, max - 1)}…` : value;
}

// Static, deterministic force-directed layout -- ticks the simulation to
// completion once (no continuous animation, no drag), rendered as plain
// SVG. Chosen deliberately as the smallest sensible graph dependency:
// d3-force is layout-only (no DOM/canvas/WebGL opinions of its own),
// so every node/edge stays a normal React-owned SVG element with normal
// click/keyboard handlers -- no canvas hit-testing needed for
// click-to-inspect.
function computeLayout(nodes: GraphNode[], edges: GraphEdge[], width: number, height: number) {
  const simNodes: SimNode[] = nodes.map((node) => ({ id: node.id, node }));
  const nodeIds = new Set(simNodes.map((n) => n.id));
  const simLinks: SimLink[] = edges
    .filter((edge) => nodeIds.has(edge.source_asset_id) && nodeIds.has(edge.target_asset_id))
    .map((edge) => ({ source: edge.source_asset_id, target: edge.target_asset_id, edge }));

  const simulation = forceSimulation(simNodes)
    .force(
      "link",
      forceLink<SimNode, SimLink>(simLinks)
        .id((d) => d.id)
        .distance(90)
        .strength(0.5),
    )
    .force("charge", forceManyBody().strength(-220))
    .force("center", forceCenter(width / 2, height / 2))
    .force("collide", forceCollide(34))
    .stop();

  const TICKS = 300;
  for (let i = 0; i < TICKS; i += 1) {
    simulation.tick();
  }

  // Clamp into the viewport so labels near the boundary stay legible
  // instead of clipping out of the visible SVG canvas.
  const pad = 44;
  simNodes.forEach((n) => {
    n.x = Math.max(pad, Math.min(width - pad, n.x ?? width / 2));
    n.y = Math.max(pad, Math.min(height - pad, n.y ?? height / 2));
  });

  return { simNodes, simLinks };
}

export function GraphView({ nodes, edges, seedAssetId, onNodeClick, width = 720, height = 480 }: GraphViewProps) {
  const { simNodes, simLinks } = useMemo(
    () => computeLayout(nodes, edges, width, height),
    [nodes, edges, width, height],
  );

  if (nodes.length === 0) {
    return <p className="text-sm text-slate-500">No relationships to display at this depth.</p>;
  }

  return (
    <svg
      role="img"
      aria-label="Attack surface graph"
      width="100%"
      viewBox={`0 0 ${width} ${height}`}
      className="rounded border bg-white"
    >
      <g>
        {simLinks.map((link, index) => {
          const source = asSimNode(link.source);
          const target = asSimNode(link.target);
          return (
            <line
              key={`${link.edge.id}-${index}`}
              x1={source.x}
              y1={source.y}
              x2={target.x}
              y2={target.y}
              stroke="#cbd5e1"
              strokeWidth={1.5}
            />
          );
        })}
      </g>
      <g>
        {simNodes.map((simNode) => {
          const isSeed = simNode.id === seedAssetId;
          const label = `${simNode.node.value} (${simNode.node.asset_type})`;
          return (
            <g
              key={simNode.id}
              transform={`translate(${simNode.x},${simNode.y})`}
              className={onNodeClick ? "cursor-pointer" : undefined}
              onClick={onNodeClick ? () => onNodeClick(simNode.node) : undefined}
              role={onNodeClick ? "button" : undefined}
              tabIndex={onNodeClick ? 0 : undefined}
              onKeyDown={
                onNodeClick
                  ? (event) => {
                      if (event.key === "Enter" || event.key === " ") {
                        event.preventDefault();
                        onNodeClick(simNode.node);
                      }
                    }
                  : undefined
              }
              aria-label={label}
            >
              <circle
                r={isSeed ? 12 : 8}
                fill={colorForType(simNode.node.asset_type)}
                stroke={isSeed ? "#0f172a" : "#ffffff"}
                strokeWidth={isSeed ? 2 : 1.5}
              />
              <text y={isSeed ? 26 : 20} textAnchor="middle" fontSize={10} className="fill-slate-700">
                {truncateLabel(simNode.node.value)}
              </text>
            </g>
          );
        })}
      </g>
    </svg>
  );
}
