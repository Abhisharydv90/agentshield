"use client";

import { useMemo } from "react";
import type {
  EvidenceEdge,
  EvidenceNode,
} from "@/lib/evidence-client";

type EvidenceGraphProps = {
  nodes: EvidenceNode[];
  edges: EvidenceEdge[];
  selectedId?: string | null;
  onSelect?: (node: EvidenceNode) => void;
};

type Point = {
  x: number;
  y: number;
};

export function EvidenceGraph({
  nodes,
  edges,
  selectedId,
  onSelect,
}: EvidenceGraphProps) {
  const width = 760;
  const height = 460;
  const cx = width / 2;
  const cy = height / 2;

  const positions = useMemo(() => {
    const result: Record<string, Point> = {};

    if (nodes.length === 0) {
      return result;
    }

    const radius = Math.min(
      175,
      90 + nodes.length * 14
    );

    nodes.forEach((node, index) => {
      const angle =
        (index / Math.max(nodes.length, 1)) *
        Math.PI *
        2 -
        Math.PI / 2;

      result[node.evidence_id] = {
        x: cx + Math.cos(angle) * radius,
        y: cy + Math.sin(angle) * radius,
      };
    });

    return result;
  }, [nodes, cx, cy]);

  return (
    <div className="border border-emerald-500/15 bg-black/50 p-3">
      <div className="mb-3 flex items-center justify-between">
        <div>
          <div className="text-[10px] font-mono tracking-[0.28em] uppercase text-emerald-400">
            Evidence Graph
          </div>
          <div className="mt-1 text-[9px] font-mono text-slate-600">
            Causal runtime lineage
          </div>
        </div>

        <div className="text-[9px] font-mono text-slate-500">
          {nodes.length} nodes · {edges.length} edges
        </div>
      </div>

      <div className="overflow-hidden border border-emerald-500/10 bg-black">
        <svg
          viewBox={`0 0 ${width} ${height}`}
          className="h-auto w-full"
          role="img"
          aria-label="Evidence graph"
        >
          <defs>
            <marker
              id="evidence-arrow"
              markerWidth="7"
              markerHeight="7"
              refX="6"
              refY="3.5"
              orient="auto"
            >
              <path
                d="M0,0 L7,3.5 L0,7 z"
                fill="currentColor"
              />
            </marker>
          </defs>

          <rect
            x="0"
            y="0"
            width={width}
            height={height}
            fill="black"
          />

          <circle
            cx={cx}
            cy={cy}
            r="150"
            fill="none"
            stroke="currentColor"
            strokeOpacity="0.08"
            strokeDasharray="3 8"
          />

          {edges.map((edge) => {
            const from = positions[
              edge.from_evidence_id
            ];

            const to = positions[
              edge.to_evidence_id
            ];

            if (!from || !to) {
              return null;
            }

            return (
              <line
                key={edge.edge_id}
                x1={from.x}
                y1={from.y}
                x2={to.x}
                y2={to.y}
                stroke="currentColor"
                strokeOpacity="0.32"
                strokeWidth="1.5"
                markerEnd="url(#evidence-arrow)"
                className="text-emerald-400"
              />
            );
          })}

          {nodes.map((node) => {
            const point =
              positions[node.evidence_id];

            if (!point) {
              return null;
            }

            const selected =
              selectedId ===
              node.evidence_id;

            const blocked =
              node.metadata_redacted
                ?.action_taken ===
              "blocked";

            return (
              <g
                key={node.evidence_id}
                className="cursor-pointer"
                onClick={() =>
                  onSelect?.(node)
                }
              >
                <circle
                  cx={point.x}
                  cy={point.y}
                  r={selected ? 16 : 12}
                  fill="black"
                  stroke="currentColor"
                  strokeWidth={selected ? 2 : 1}
                  strokeOpacity={
                    selected ? 1 : 0.65
                  }
                  className={
                    blocked
                      ? "text-rose-400"
                      : "text-emerald-400"
                  }
                />

                <circle
                  cx={point.x}
                  cy={point.y}
                  r="3"
                  fill="currentColor"
                  className={
                    blocked
                      ? "text-rose-400"
                      : "text-emerald-400"
                  }
                />

                <text
                  x={point.x}
                  y={point.y + 31}
                  textAnchor="middle"
                  className="fill-slate-500 text-[8px]"
                >
                  {node.evidence_id.slice(
                    0,
                    8
                  )}
                </text>

                <text
                  x={point.x}
                  y={point.y - 23}
                  textAnchor="middle"
                  className="fill-slate-700 text-[7px]"
                >
                  {node.node_type}
                </text>
              </g>
            );
          })}

          {nodes.length === 0 && (
            <text
              x={cx}
              y={cy}
              textAnchor="middle"
              className="fill-slate-600 text-[10px]"
            >
              NO EVIDENCE
            </text>
          )}
        </svg>
      </div>
    </div>
  );
}