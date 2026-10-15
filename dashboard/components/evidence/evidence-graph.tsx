"use client";

import {
  useMemo,
  useRef,
  useState,
  type KeyboardEvent,
  type PointerEvent as ReactPointerEvent,
  type WheelEvent as ReactWheelEvent,
} from "react";

import {
  Maximize2,
  Minus,
  Plus,
  RotateCcw,
  ShieldAlert,
  ShieldCheck,
} from "lucide-react";

import type {
  EvidenceEdge,
  EvidenceNode,
} from "@/lib/evidence-client";

type EvidenceGraphProps = {
  nodes: EvidenceNode[];
  edges: EvidenceEdge[];
  selectedId?: string | null;
  truncated?: boolean;
  onSelect?: (node: EvidenceNode) => void;
};

type Point = {
  x: number;
  y: number;
};

type LayoutNode = Point & {
  depth: number;
  component: number;
};

type DragState = {
  active: boolean;
  startX: number;
  startY: number;
  originX: number;
  originY: number;
};

const WIDTH = 960;
const HEIGHT = 560;
const CENTER_X = WIDTH / 2;
const CENTER_Y = HEIGHT / 2;

const MIN_ZOOM = 0.45;
const MAX_ZOOM = 2.5;
const ZOOM_STEP = 0.15;

const BASE_RING_GAP = 105;
const BASE_RADIUS = 13;

function clamp(
  value: number,
  min: number,
  max: number,
): number {
  return Math.min(
    Math.max(value, min),
    max,
  );
}

function nodeSort(
  a: EvidenceNode,
  b: EvidenceNode,
): number {
  const timeCompare =
    new Date(a.created_at).getTime() -
    new Date(b.created_at).getTime();

  if (timeCompare !== 0) {
    return timeCompare;
  }

  return a.evidence_id.localeCompare(
    b.evidence_id,
  );
}

function buildAdjacency(
  nodes: EvidenceNode[],
  edges: EvidenceEdge[],
): Map<string, string[]> {
  const known = new Set(
    nodes.map(
      (node) => node.evidence_id,
    ),
  );

  const adjacency = new Map<
    string,
    string[]
  >();

  for (const node of nodes) {
    adjacency.set(
      node.evidence_id,
      [],
    );
  }

  for (const edge of edges) {
    if (
      !known.has(
        edge.from_evidence_id,
      ) ||
      !known.has(
        edge.to_evidence_id,
      )
    ) {
      continue;
    }

    adjacency
      .get(edge.from_evidence_id)
      ?.push(edge.to_evidence_id);

    adjacency
      .get(edge.to_evidence_id)
      ?.push(edge.from_evidence_id);
  }

  for (const [
    id,
    neighbors,
  ] of adjacency.entries()) {
    neighbors.sort((a, b) =>
      a.localeCompare(b),
    );

    adjacency.set(
      id,
      neighbors,
    );
  }

  return adjacency;
}

function buildComponents(
  nodes: EvidenceNode[],
  edges: EvidenceEdge[],
): Map<string, number> {
  const adjacency = buildAdjacency(
    nodes,
    edges,
  );

  const components = new Map<
    string,
    number
  >();

  const sorted = [...nodes].sort(
    nodeSort,
  );

  let componentId = 0;

  for (const node of sorted) {
    if (
      components.has(
        node.evidence_id,
      )
    ) {
      continue;
    }

    const queue = [
      node.evidence_id,
    ];

    components.set(
      node.evidence_id,
      componentId,
    );

    let cursor = 0;

    while (cursor < queue.length) {
      const current =
        queue[cursor];

      cursor += 1;

      for (const neighbor of
        adjacency.get(current) ?? []) {
        if (
          components.has(
            neighbor,
          )
        ) {
          continue;
        }

        components.set(
          neighbor,
          componentId,
        );

        queue.push(neighbor);
      }
    }

    componentId += 1;
  }

  return components;
}

function buildDepths(
  nodes: EvidenceNode[],
  edges: EvidenceEdge[],
  selectedId?: string | null,
): {
  depths: Map<string, number>;
  components: Map<string, number>;
} {
  const sorted = [...nodes].sort(
    nodeSort,
  );

  const adjacency =
    buildAdjacency(
      nodes,
      edges,
    );

  const components =
    buildComponents(
      nodes,
      edges,
    );

  const depths = new Map<
    string,
    number
  >();

  if (sorted.length === 0) {
    return {
      depths,
      components,
    };
  }

  const root =
    selectedId &&
    nodes.some(
      (node) =>
        node.evidence_id ===
        selectedId,
    )
      ? selectedId
      : sorted[0]
          .evidence_id;

  const queue: string[] = [
    root,
  ];

  depths.set(root, 0);

  let cursor = 0;

  while (cursor < queue.length) {
    const current =
      queue[cursor];

    cursor += 1;

    const currentDepth =
      depths.get(current) ?? 0;

    const neighbors =
      adjacency.get(current) ??
      [];

    for (const neighbor of
      neighbors) {
      if (
        depths.has(neighbor)
      ) {
        continue;
      }

      depths.set(
        neighbor,
        currentDepth + 1,
      );

      queue.push(neighbor);
    }
  }

  /*
   * Disconnected components remain visible.
   * Their roots are placed in subsequent
   * outer layers rather than discarded.
   */
  let disconnectedDepth = 1;

  for (const node of sorted) {
    if (
      depths.has(
        node.evidence_id,
      )
    ) {
      continue;
    }

    depths.set(
      node.evidence_id,
      disconnectedDepth,
    );

    disconnectedDepth += 1;
  }

  return {
    depths,
    components,
  };
}

function buildLayout(
  nodes: EvidenceNode[],
  edges: EvidenceEdge[],
  selectedId?: string | null,
): Map<
  string,
  LayoutNode
> {
  const sorted = [...nodes].sort(
    nodeSort,
  );

  const {
    depths,
    components,
  } = buildDepths(
    sorted,
    edges,
    selectedId,
  );

  const buckets = new Map<
    number,
    EvidenceNode[]
  >();

  for (const node of sorted) {
    const depth =
      depths.get(
        node.evidence_id,
      ) ?? 0;

    const bucket =
      buckets.get(depth) ??
      [];

    bucket.push(node);

    buckets.set(
      depth,
      bucket,
    );
  }

  const result = new Map<
    string,
    LayoutNode
  >();

  const maxDepth = Math.max(
    0,
    ...Array.from(
      buckets.keys(),
    ),
  );

  for (
    let depth = 0;
    depth <= maxDepth;
    depth += 1
  ) {
    const bucket =
      buckets.get(depth) ??
      [];

    if (bucket.length === 0) {
      continue;
    }

    if (depth === 0) {
      const root =
        bucket[0];

      result.set(
        root.evidence_id,
        {
          x: CENTER_X,
          y: CENTER_Y,
          depth,
          component:
            components.get(
              root.evidence_id,
            ) ?? 0,
        },
      );

      continue;
    }

    const radius = Math.min(
      235,
      BASE_RING_GAP +
        (depth - 1) *
          105,
    );

    const angleOffset =
      depth % 2 === 0
        ? -Math.PI / 2
        : -Math.PI / 2 +
          Math.PI /
            Math.max(
              bucket.length,
              1,
            );

    bucket.forEach(
      (node, index) => {
        const angle =
          angleOffset +
          (index /
            Math.max(
              bucket.length,
              1,
            )) *
            Math.PI *
            2;

        result.set(
          node.evidence_id,
          {
            x:
              CENTER_X +
              Math.cos(angle) *
                radius,
            y:
              CENTER_Y +
              Math.sin(angle) *
                radius,
            depth,
            component:
              components.get(
                node.evidence_id,
              ) ?? 0,
          },
        );
      },
    );
  }

  return result;
}

function zoomAround(
  currentZoom: number,
  direction: 1 | -1,
): number {
  return clamp(
    currentZoom +
      direction *
        ZOOM_STEP,
    MIN_ZOOM,
    MAX_ZOOM,
  );
}

function edgeTouchesNode(
  edge: EvidenceEdge,
  evidenceId: string | null,
): boolean {
  if (!evidenceId) {
    return false;
  }

  return (
    edge.from_evidence_id ===
      evidenceId ||
    edge.to_evidence_id ===
      evidenceId
  );
}

function getNodeAction(
  node: EvidenceNode,
): string {
  const value =
    node.metadata_redacted
      ?.action_taken;

  return typeof value === "string"
    ? value
    : "unknown";
}

function getNodeThreat(
  node: EvidenceNode,
): string {
  const value =
    node.metadata_redacted
      ?.threat_category;

  return typeof value === "string"
    ? value
    : "none";
}

function truncateLabel(
  value: string,
  maxLength: number,
): string {
  if (
    value.length <=
    maxLength
  ) {
    return value;
  }

  return `${value.slice(
    0,
    maxLength - 1,
  )}…`;
}

export function EvidenceGraph({
  nodes,
  edges,
  selectedId,
  truncated = false,
  onSelect,
}: EvidenceGraphProps) {
  const [
    zoom,
    setZoom,
  ] = useState(1);

  const [
    pan,
    setPan,
  ] = useState<Point>({
    x: 0,
    y: 0,
  });

  const [
    hoveredId,
    setHoveredId,
  ] = useState<
    string | null
  >(null);

  const dragRef =
    useRef<DragState>({
      active: false,
      startX: 0,
      startY: 0,
      originX: 0,
      originY: 0,
    });

  const positions =
    useMemo(
      () =>
        buildLayout(
          nodes,
          edges,
          selectedId,
        ),
      [
        nodes,
        edges,
        selectedId,
      ],
    );

  const selectedNode =
    useMemo(
      () =>
        nodes.find(
          (node) =>
            node.evidence_id ===
            selectedId,
        ) ?? null,
      [
        nodes,
        selectedId,
      ],
    );

  const hoveredNode =
    useMemo(
      () =>
        nodes.find(
          (node) =>
            node.evidence_id ===
            hoveredId,
        ) ?? null,
      [
        nodes,
        hoveredId,
      ],
    );

  const focusNode =
    hoveredNode ??
    selectedNode;

  const componentCount =
    useMemo(
      () =>
        new Set(
          Array.from(
            positions.values(),
            (point) =>
              point.component,
          ),
        ).size,
      [positions],
    );

  const rootNodeId =
    selectedNode?.evidence_id ??
    [...nodes].sort(
      nodeSort,
    )[0]?.evidence_id ??
    null;

  function resetView() {
    setZoom(1);

    setPan({
      x: 0,
      y: 0,
    });
  }

  function fitView() {
    if (nodes.length <= 1) {
      resetView();
      return;
    }

    const maxDepth =
      Math.max(
        0,
        ...Array.from(
          positions.values(),
          (point) =>
            point.depth,
        ),
      );

    const requiredRadius =
      BASE_RING_GAP +
      Math.max(
        0,
        maxDepth - 1,
      ) *
        105;

    const horizontalScale =
      (WIDTH * 0.43) /
      Math.max(
        requiredRadius,
        1,
      );

    const verticalScale =
      (HEIGHT * 0.38) /
      Math.max(
        requiredRadius,
        1,
      );

    setZoom(
      clamp(
        Math.min(
          horizontalScale,
          verticalScale,
        ),
        MIN_ZOOM,
        1,
      ),
    );

    setPan({
      x: 0,
      y: 0,
    });
  }

  function handleWheel(
    event: ReactWheelEvent<
      SVGSVGElement
    >,
  ) {
    event.preventDefault();

    setZoom((current) =>
      clamp(
        current +
          (event.deltaY < 0
            ? ZOOM_STEP
            : -ZOOM_STEP),
        MIN_ZOOM,
        MAX_ZOOM,
      ),
    );
  }

  function handlePointerDown(
    event: ReactPointerEvent<
      SVGSVGElement
    >,
  ) {
    const target =
      event.target as Element;

    if (
      target.closest(
        "[data-evidence-node='true']",
      )
    ) {
      return;
    }

    dragRef.current = {
      active: true,
      startX: event.clientX,
      startY: event.clientY,
      originX: pan.x,
      originY: pan.y,
    };

    event.currentTarget.setPointerCapture(
      event.pointerId,
    );
  }

  function handlePointerMove(
    event: ReactPointerEvent<
      SVGSVGElement
    >,
  ) {
    if (
      !dragRef.current.active
    ) {
      return;
    }

    const deltaX =
      event.clientX -
      dragRef.current.startX;

    const deltaY =
      event.clientY -
      dragRef.current.startY;

    setPan({
      x:
        dragRef.current.originX +
        deltaX,
      y:
        dragRef.current.originY +
        deltaY,
    });
  }

  function handlePointerUp(
    event: ReactPointerEvent<
      SVGSVGElement
    >,
  ) {
    dragRef.current.active =
      false;

    if (
      event.currentTarget.hasPointerCapture(
        event.pointerId,
      )
    ) {
      event.currentTarget.releasePointerCapture(
        event.pointerId,
      );
    }
  }

  function handleKeyDown(
    event: KeyboardEvent<SVGGElement>,
    node: EvidenceNode,
  ) {
    if (
      event.key ===
        "Enter" ||
      event.key === " "
    ) {
      event.preventDefault();
      onSelect?.(node);
      return;
    }

    if (event.key === "Escape") {
      setHoveredId(null);
    }
  }

  return (
    <section className="border border-emerald-500/15 bg-black/50 p-3">
      <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
        <div>
          <div className="flex items-center gap-2 text-[10px] font-mono tracking-[0.28em] uppercase text-emerald-400">
            <ShieldCheck className="h-3.5 w-3.5" />
            Evidence Graph
          </div>

          <div className="mt-1 text-[9px] font-mono text-slate-600">
            Deterministic causal lineage ·
            drag to pan · wheel to zoom
          </div>
        </div>

        <div className="flex items-center gap-2">
          <div className="mr-1 text-right text-[9px] font-mono text-slate-500">
            <div>
              {nodes.length} nodes ·{" "}
              {edges.length} edges
            </div>

            {componentCount > 1 && (
              <div className="text-[8px] text-slate-700">
                {componentCount} components
              </div>
            )}
          </div>

          <button
            type="button"
            onClick={() =>
              setZoom((current) =>
                zoomAround(
                  current,
                  -1,
                ),
              )
            }
            aria-label="Zoom out"
            title="Zoom out"
            className="border border-slate-700 p-1.5 text-slate-500 transition hover:border-emerald-500/30 hover:text-emerald-400"
          >
            <Minus className="h-3.5 w-3.5" />
          </button>

          <button
            type="button"
            onClick={() =>
              setZoom((current) =>
                zoomAround(
                  current,
                  1,
                ),
              )
            }
            aria-label="Zoom in"
            title="Zoom in"
            className="border border-slate-700 p-1.5 text-slate-500 transition hover:border-emerald-500/30 hover:text-emerald-400"
          >
            <Plus className="h-3.5 w-3.5" />
          </button>

          <button
            type="button"
            onClick={fitView}
            aria-label="Fit graph"
            title="Fit graph"
            className="border border-slate-700 p-1.5 text-slate-500 transition hover:border-cyan-500/30 hover:text-cyan-400"
          >
            <Maximize2 className="h-3.5 w-3.5" />
          </button>

          <button
            type="button"
            onClick={resetView}
            aria-label="Reset graph view"
            title="Reset graph view"
            className="border border-slate-700 p-1.5 text-slate-500 transition hover:border-emerald-500/30 hover:text-emerald-400"
          >
            <RotateCcw className="h-3.5 w-3.5" />
          </button>
        </div>
      </div>

      {truncated && (
        <div className="mb-3 flex items-center gap-2 border border-amber-500/20 bg-amber-500/5 px-3 py-2 text-[9px] font-mono uppercase tracking-[0.14em] text-amber-300">
          <ShieldAlert className="h-3.5 w-3.5" />
          Graph bounded · additional evidence omitted
        </div>
      )}

      <div className="overflow-hidden border border-emerald-500/10 bg-black">
        <svg
          viewBox={`0 0 ${WIDTH} ${HEIGHT}`}
          className="block h-auto w-full select-none touch-none"
          role="img"
          aria-label="Interactive evidence graph showing causal relationships between evidence nodes"
          onWheel={handleWheel}
          onPointerDown={handlePointerDown}
          onPointerMove={handlePointerMove}
          onPointerUp={handlePointerUp}
          onPointerCancel={handlePointerUp}
        >
          <defs>
            <marker
              id="evidence-arrow"
              markerWidth="8"
              markerHeight="8"
              refX="7"
              refY="4"
              orient="auto"
              markerUnits="strokeWidth"
            >
              <path
                d="M0,0 L8,4 L0,8 Z"
                fill="currentColor"
                className="text-emerald-400/70"
              />
            </marker>

            <filter
              id="evidence-glow"
              x="-80%"
              y="-80%"
              width="260%"
              height="260%"
            >
              <feGaussianBlur
                stdDeviation="3"
                result="blur"
              />

              <feMerge>
                <feMergeNode in="blur" />
                <feMergeNode in="SourceGraphic" />
              </feMerge>
            </filter>
          </defs>

          <rect
            x="0"
            y="0"
            width={WIDTH}
            height={HEIGHT}
            fill="black"
          />

          <g
            transform={`translate(${CENTER_X + pan.x} ${CENTER_Y + pan.y}) scale(${zoom}) translate(${-CENTER_X} ${-CENTER_Y})`}
          >
            <circle
              cx={CENTER_X}
              cy={CENTER_Y}
              r="54"
              fill="none"
              stroke="currentColor"
              strokeOpacity="0.08"
              strokeDasharray="2 7"
              className="text-cyan-400"
            />

            {rootNodeId && (
              <circle
                cx={
                  positions.get(
                    rootNodeId,
                  )?.x ?? CENTER_X
                }
                cy={
                  positions.get(
                    rootNodeId,
                  )?.y ?? CENTER_Y
                }
                r="25"
                fill="none"
                stroke="currentColor"
                strokeOpacity="0.14"
                strokeDasharray="2 5"
                className="text-cyan-400"
              />
            )}

            {edges.map((edge) => {
              const from =
                positions.get(
                  edge.from_evidence_id,
                );

              const to =
                positions.get(
                  edge.to_evidence_id,
                );

              if (!from || !to) {
                return null;
              }

              const highlighted =
                edgeTouchesNode(
                  edge,
                  hoveredId,
                );

              const selectedEdge =
                edgeTouchesNode(
                  edge,
                  selectedId ??
                    null,
                );

              const edgeActive =
                highlighted ||
                selectedEdge;

              const midpointX =
                (from.x + to.x) /
                2;

              const midpointY =
                (from.y + to.y) /
                2;

              const relation =
                truncateLabel(
                  edge.relation,
                  22,
                );

              return (
                <g
                  key={edge.edge_id}
                  pointerEvents="none"
                >
                  <line
                    x1={from.x}
                    y1={from.y}
                    x2={to.x}
                    y2={to.y}
                    stroke="currentColor"
                    strokeOpacity={
                      edgeActive
                        ? 0.86
                        : 0.22
                    }
                    strokeWidth={
                      edgeActive
                        ? 2.2
                        : 1.2
                    }
                    markerEnd="url(#evidence-arrow)"
                    className="text-emerald-400"
                  />

                  {relation && (
                    <g
                      opacity={
                        edgeActive
                          ? 1
                          : 0.42
                      }
                    >
                      <rect
                        x={
                          midpointX -
                          Math.max(
                            relation.length *
                              2.55,
                            24,
                          )
                        }
                        y={
                          midpointY -
                          9
                        }
                        width={Math.max(
                          relation.length *
                            5.1,
                          48,
                        )}
                        height="16"
                        rx="3"
                        fill="black"
                        fillOpacity="0.88"
                        stroke="currentColor"
                        strokeOpacity={
                          edgeActive
                            ? 0.16
                            : 0.07
                        }
                        className="text-emerald-400"
                      />

                      <text
                        x={midpointX}
                        y={
                          midpointY +
                          3.5
                        }
                        textAnchor="middle"
                        className="fill-slate-600 text-[6px] font-mono"
                      >
                        {relation}
                      </text>
                    </g>
                  )}
                </g>
              );
            })}

            {nodes.map((node) => {
              const point =
                positions.get(
                  node.evidence_id,
                );

              if (!point) {
                return null;
              }

              const selected =
                node.evidence_id ===
                selectedId;

              const hovered =
                node.evidence_id ===
                hoveredId;

              const connected =
                hoveredId
                  ? edges.some(
                      (edge) =>
                        edgeTouchesNode(
                          edge,
                          node.evidence_id,
                        ) &&
                        edgeTouchesNode(
                          edge,
                          hoveredId,
                        ),
                    )
                  : false;

              const blocked =
                getNodeAction(
                  node,
                ) === "blocked";

              const dimmed =
                hoveredId !== null &&
                !hovered &&
                !connected;

              const nodeClass =
                blocked
                  ? "text-rose-400"
                  : hovered
                    ? "text-cyan-400"
                    : selected
                      ? "text-cyan-400"
                      : "text-emerald-400";

              const nodeRadius =
                hovered || selected
                  ? 18
                  : BASE_RADIUS;

              return (
                <g
                  key={node.evidence_id}
                  data-evidence-node="true"
                  tabIndex={0}
                  role="button"
                  aria-label={`Evidence ${node.evidence_id.slice(0, 8)} ${node.node_type}`}
                  aria-pressed={selected}
                  className={`cursor-pointer outline-none ${
                    dimmed
                      ? "opacity-35"
                      : ""
                  }`}
                  onClick={() =>
                    onSelect?.(node)
                  }
                  onKeyDown={(event) =>
                    handleKeyDown(
                      event,
                      node,
                    )
                  }
                  onMouseEnter={() =>
                    setHoveredId(
                      node.evidence_id,
                    )
                  }
                  onMouseLeave={() =>
                    setHoveredId(null)
                  }
                >
                  {(selected ||
                    hovered) && (
                    <circle
                      cx={point.x}
                      cy={point.y}
                      r="26"
                      fill="currentColor"
                      fillOpacity="0.04"
                      stroke="currentColor"
                      strokeOpacity="0.22"
                      className={
                        hovered
                          ? "text-cyan-400"
                          : "text-emerald-400"
                      }
                      filter="url(#evidence-glow)"
                    />
                  )}

                  <circle
                    cx={point.x}
                    cy={point.y}
                    r={nodeRadius}
                    fill="black"
                    stroke="currentColor"
                    strokeWidth={
                      selected ||
                      hovered
                        ? 2
                        : 1.2
                    }
                    strokeOpacity={
                      selected ||
                      hovered
                        ? 1
                        : 0.72
                    }
                    className={
                      nodeClass
                    }
                  />

                  <circle
                    cx={point.x}
                    cy={point.y}
                    r="4"
                    fill="currentColor"
                    className={
                      nodeClass
                    }
                  />

                  {blocked && (
                    <circle
                      cx={
                        point.x + 10
                      }
                      cy={
                        point.y - 10
                      }
                      r="5"
                      fill="black"
                      stroke="currentColor"
                      strokeWidth="1"
                      className="text-rose-400"
                    />
                  )}

                  {blocked && (
                    <foreignObject
                      x={
                        point.x + 5
                      }
                      y={
                        point.y - 15
                      }
                      width="10"
                      height="10"
                      pointerEvents="none"
                    >
                      <ShieldAlert className="h-[10px] w-[10px] text-rose-400" />
                    </foreignObject>
                  )}

                  <text
                    x={point.x}
                    y={
                      point.y + 32
                    }
                    textAnchor="middle"
                    className={`text-[8px] font-mono ${
                      selected ||
                      hovered
                        ? "fill-cyan-400"
                        : "fill-slate-500"
                    }`}
                  >
                    {node.evidence_id.slice(
                      0,
                      8,
                    )}
                  </text>

                  <text
                    x={point.x}
                    y={
                      point.y - 24
                    }
                    textAnchor="middle"
                    className={`text-[7px] font-mono ${
                      selected ||
                      hovered
                        ? "fill-slate-500"
                        : "fill-slate-700"
                    }`}
                  >
                    {truncateLabel(
                      node.node_type,
                      20,
                    )}
                  </text>

                  {hovered && (
                    <g pointerEvents="none">
                      <rect
                        x={
                          point.x -
                          94
                        }
                        y={
                          point.y +
                          42
                        }
                        width="188"
                        height="56"
                        rx="4"
                        fill="black"
                        fillOpacity="0.96"
                        stroke="currentColor"
                        strokeOpacity="0.16"
                        className="text-cyan-400"
                      />

                      <text
                        x={point.x}
                        y={
                          point.y +
                          56
                        }
                        textAnchor="middle"
                        className="fill-cyan-400 text-[7px] font-mono"
                      >
                        {node.node_type}
                      </text>

                      <text
                        x={point.x}
                        y={
                          point.y +
                          70
                        }
                        textAnchor="middle"
                        className="fill-slate-500 text-[6px] font-mono"
                      >
                        action=
                        {getNodeAction(
                          node,
                        )}
                      </text>

                      <text
                        x={point.x}
                        y={
                          point.y +
                          82
                        }
                        textAnchor="middle"
                        className="fill-slate-600 text-[6px] font-mono"
                      >
                        threat=
                        {getNodeThreat(
                          node,
                        )}
                      </text>

                      <text
                        x={point.x}
                        y={
                          point.y +
                          92
                        }
                        textAnchor="middle"
                        className="fill-slate-700 text-[5.5px] font-mono"
                      >
                        {node.evidence_id.slice(
                          0,
                          18,
                        )}
                      </text>
                    </g>
                  )}
                </g>
              );
            })}

            {nodes.length === 0 && (
              <g>
                <circle
                  cx={CENTER_X}
                  cy={CENTER_Y}
                  r="28"
                  fill="none"
                  stroke="currentColor"
                  strokeOpacity="0.12"
                  strokeDasharray="3 6"
                  className="text-slate-500"
                />

                <text
                  x={CENTER_X}
                  y={
                    CENTER_Y + 4
                  }
                  textAnchor="middle"
                  className="fill-slate-600 text-[10px] font-mono"
                >
                  NO EVIDENCE
                </text>
              </g>
            )}
          </g>
        </svg>
      </div>

      <div className="mt-3 flex flex-wrap items-center justify-between gap-3 border-t border-emerald-500/10 pt-3">
        <div className="flex flex-wrap items-center gap-4 text-[8px] font-mono uppercase tracking-[0.16em] text-slate-600">
          <span className="flex items-center gap-1.5">
            <span className="h-2 w-2 rounded-full border border-emerald-400 bg-black" />
            evidence
          </span>

          <span className="flex items-center gap-1.5">
            <span className="h-2 w-2 rounded-full border border-cyan-400 bg-black" />
            focused
          </span>

          <span className="flex items-center gap-1.5">
            <span className="h-2 w-2 rounded-full border border-rose-400 bg-black" />
            blocked
          </span>

          {componentCount > 1 && (
            <span className="text-slate-700">
              disconnected components
            </span>
          )}
        </div>

        <div className="text-[8px] font-mono text-slate-700">
          {focusNode
            ? `${focusNode.node_type} · ${getNodeAction(focusNode)}`
            : "no node focused"}{" "}
          · zoom{" "}
          {Math.round(
            zoom * 100,
          )}
          %
        </div>
      </div>
    </section>
  );
}