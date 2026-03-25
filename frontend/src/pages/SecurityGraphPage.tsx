import "@xyflow/react/dist/style.css";
import { useEffect } from "react";
import {
  ReactFlow,
  ReactFlowProvider,
  Background,
  Controls,
  MiniMap,
  useNodesState,
  useEdgesState,
  useReactFlow,
  BackgroundVariant,
} from "@xyflow/react";
import type {
  Node,
  Edge,
  NodeProps,
} from "@xyflow/react";
import { useSecurityGraph } from "@/hooks/useSecurityGraph";
import { useRegion } from "@/hooks/useRegion";
import type { GraphNode, GraphEdge } from "@/types/securityGraph";

/* ── Severity border colors ─────────────────── */

const severityBorder: Record<string, string> = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#eab308",
  low: "#3b82f6",
  none: "",
};

/* ── Service icons ───────────────────────────── */

function serviceIcon(service: string): string {
  switch (service.toLowerCase()) {
    case "s3": return "🪣";
    case "ec2": return "🖥️";
    case "iam": return "🔑";
    case "rds": return "🗄️";
    case "lambda": return "λ";
    case "security_group":
    case "sg": return "🛡️";
    case "vpc": return "🌐";
    case "cloudtrail": return "📋";
    case "kms": return "🔐";
    default: return "📦";
  }
}

/* ── ResourceNode ────────────────────────────── */

interface ResourceNodeData {
  label: string;
  resource_type: string;
  service: string;
  violation_count: number;
  max_severity: string;
  risk_score: number;
  [key: string]: unknown;
}

function ResourceNode({
  data,
}: NodeProps<Node<ResourceNodeData>>) {
  const border =
    severityBorder[data.max_severity] ||
    severityBorder.none;
  const borderStyle = border
    ? `2px solid ${border}`
    : "1px solid #e5e7eb";

  return (
    <div
      style={{ border: borderStyle }}
      className={[
        "bg-white dark:bg-[#111]",
        "rounded-xl px-3 py-2 shadow-sm",
        "min-w-[140px] max-w-[180px]",
        "text-left",
      ].join(" ")}
    >
      {/* Icon + type */}
      <div className="flex items-center gap-1.5 mb-1">
        <span className="text-base leading-none">
          {serviceIcon(data.service)}
        </span>
        <span
          className={[
            "text-[10px] font-semibold uppercase",
            "tracking-wider text-gray-400",
            "dark:text-gray-600 truncate",
          ].join(" ")}
        >
          {data.resource_type.replace(/_/g, " ")}
        </span>
      </div>

      {/* Label */}
      <p
        className={[
          "text-xs font-medium text-gray-900",
          "dark:text-white truncate mb-1.5",
        ].join(" ")}
        title={data.label}
      >
        {data.label}
      </p>

      {/* Violation badge + risk score */}
      <div className="flex items-center gap-2">
        <span
          className={`
            text-[10px] font-semibold px-1.5 py-0.5
            rounded-full
            ${
              data.violation_count > 0
                ? "bg-red-100 dark:bg-red-500/20 text-red-600 dark:text-red-400"
                : "bg-gray-100 dark:bg-white/5 text-gray-400 dark:text-gray-600"
            }
          `}
        >
          {data.violation_count} violations
        </span>
        <span className="text-[10px] text-gray-400 dark:text-gray-600 ml-auto">
          {data.risk_score}/100
        </span>
      </div>
    </div>
  );
}

/* ── node + edge types (stable references) ───── */

const nodeTypes = { resourceNode: ResourceNode };

/* ── conversion helpers ──────────────────────── */

function toFlowNodes(
  nodes: GraphNode[],
): Node<ResourceNodeData>[] {
  const cols = Math.max(
    1,
    Math.ceil(Math.sqrt(nodes.length)),
  );
  return nodes.map((n, i) => ({
    id: n.id,
    type: "resourceNode",
    position: {
      x: (i % cols) * 220,
      y: Math.floor(i / cols) * 120,
    },
    data: {
      label: n.label,
      resource_type: n.resource_type,
      service: n.service,
      violation_count: n.violation_count,
      max_severity: n.max_severity,
      risk_score: n.risk_score,
    },
  }));
}

function toFlowEdges(edges: GraphEdge[]): Edge[] {
  return edges.map((e, i) => ({
    id: `edge-${i}-${e.source}-${e.target}`,
    source: e.source,
    target: e.target,
    label: e.relationship,
    style: e.attack_path
      ? {
          stroke: "#ef4444",
          strokeWidth: 2.5,
          strokeDasharray: "5 3",
        }
      : {
          stroke: "#9ca3af",
          strokeWidth: 1.5,
        },
    animated: e.attack_path,
    data: { attack_path: e.attack_path },
  }));
}

/* ── Flow canvas (needs ReactFlowProvider ctx) ── */

function FlowCanvas({
  graphNodes,
  graphEdges,
}: {
  graphNodes: GraphNode[];
  graphEdges: GraphEdge[];
}) {
  const [nodes, , onNodesChange] =
    useNodesState<Node<ResourceNodeData>>(
      toFlowNodes(graphNodes),
    );
  const [edges, , onEdgesChange] =
    useEdgesState<Edge>(toFlowEdges(graphEdges));

  const { fitView } = useReactFlow();

  useEffect(() => {
    const t = setTimeout(
      () => fitView({ duration: 400 }),
      50,
    );
    return () => clearTimeout(t);
  }, [fitView]);

  return (
    <ReactFlow
      nodes={nodes}
      edges={edges}
      onNodesChange={onNodesChange}
      onEdgesChange={onEdgesChange}
      nodeTypes={nodeTypes}
      fitView
      minZoom={0.1}
      maxZoom={2}
      className="bg-transparent"
    >
      <Background
        variant={BackgroundVariant.Dots}
        gap={20}
        className="dark:opacity-20"
      />
      <Controls />
      <MiniMap />
    </ReactFlow>
  );
}

/* ── Stats card ──────────────────────────────── */

function StatCard({
  label,
  value,
  danger,
}: {
  label: string;
  value: number;
  danger?: boolean;
}) {
  return (
    <div
      className={[
        "flex flex-col gap-0.5",
        "bg-white dark:bg-[#111]",
        "border border-gray-100 dark:border-white/5",
        "rounded-2xl px-5 py-3 shadow-sm",
      ].join(" ")}
    >
      <span
        className={`text-2xl font-black ${
          danger
            ? "text-red-500 dark:text-red-400"
            : "text-gray-900 dark:text-white"
        }`}
      >
        {value}
      </span>
      <span className="text-xs text-gray-400 dark:text-gray-600 font-medium">
        {label}
      </span>
    </div>
  );
}

/* ── Loading skeleton ────────────────────────── */

function LoadingSkeleton() {
  return (
    <div className="space-y-4 animate-pulse">
      <div className="flex gap-4">
        {Array.from({ length: 3 }).map((_, i) => (
          <div
            key={i}
            className={[
              "h-16 flex-1 rounded-2xl",
              "bg-gray-100 dark:bg-white/5",
              "border border-gray-100 dark:border-white/5",
            ].join(" ")}
          />
        ))}
      </div>
      <div
        className={[
          "rounded-2xl border",
          "border-gray-100 dark:border-white/5",
          "bg-gray-50 dark:bg-[#0d0d0d]",
        ].join(" ")}
        style={{ height: 500 }}
      />
    </div>
  );
}

/* ── Main page ───────────────────────────────── */

export default function SecurityGraphPage() {
  const { data, isLoading, isError } =
    useSecurityGraph();
  const {
    selectedRegion,
    regions,
    setSelectedRegion,
  } = useRegion();

  const hasNodes =
    !!data && data.nodes.length > 0;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h2 className="text-xl font-bold text-gray-900 dark:text-white tracking-tight">
            Security Graph
          </h2>
          <p className="text-xs text-gray-400 dark:text-gray-600 mt-0.5">
            Resource relationships and attack paths
            across your AWS environment
          </p>
        </div>

        {/* Region selector */}
        <label className="flex items-center gap-2">
          <span className="sr-only">Region</span>
          <select
            aria-label="Region"
            value={selectedRegion}
            onChange={(e) =>
              setSelectedRegion(e.target.value)
            }
            className={[
              "text-[13px] rounded-lg",
              "border border-gray-200 dark:border-white/10",
              "bg-white dark:bg-black",
              "text-gray-700 dark:text-gray-300",
              "px-3 py-1.5 outline-none",
              "focus:ring-2 focus:ring-blue-500/30",
            ].join(" ")}
          >
            <option value="">All Regions</option>
            {regions.map((r) => (
              <option key={r} value={r}>
                {r}
              </option>
            ))}
          </select>
        </label>
      </div>

      {/* Loading */}
      {isLoading && <LoadingSkeleton />}

      {/* Error */}
      {isError && !isLoading && (
        <div
          className={[
            "bg-red-50 dark:bg-red-500/5",
            "border border-red-200 dark:border-red-500/20",
            "rounded-xl p-5",
          ].join(" ")}
        >
          <p className="text-sm text-red-700 dark:text-red-400">
            Failed to load security graph data.
            Check that the backend is running and
            retry.
          </p>
        </div>
      )}

      {/* Stats bar — only when data available */}
      {!isLoading && !isError && data && (
        <div className="flex gap-4 flex-wrap">
          <StatCard
            label="Total Nodes"
            value={data.total_nodes}
          />
          <StatCard
            label="Total Edges"
            value={data.total_edges}
          />
          <StatCard
            label="Attack Paths"
            value={data.attack_paths}
            danger
          />
        </div>
      )}

      {/* Empty state */}
      {!isLoading && !isError && data && !hasNodes && (
        <div
          className={[
            "flex flex-col items-center",
            "justify-center py-20 gap-3 text-center",
          ].join(" ")}
        >
          <svg
            className="w-12 h-12 text-gray-300 dark:text-gray-700"
            fill="none"
            stroke="currentColor"
            strokeWidth="1.2"
            viewBox="0 0 24 24"
          >
            <circle cx="5" cy="12" r="2" />
            <circle cx="19" cy="5" r="2" />
            <circle cx="19" cy="19" r="2" />
            <path
              strokeLinecap="round"
              d="M7 11l10-5M7 13l10 5"
            />
          </svg>
          <p className="text-sm font-medium text-gray-500 dark:text-gray-400">
            No resources found. Run a scan first.
          </p>
        </div>
      )}

      {/* Graph canvas */}
      {!isLoading && !isError && hasNodes && (
        <div
          data-testid="security-graph-container"
          className={[
            "relative overflow-hidden",
            "rounded-2xl border",
            "border-gray-100 dark:border-white/5",
            "bg-gray-50 dark:bg-[#0d0d0d]",
          ].join(" ")}
          style={{
            height: "calc(100vh - 320px)",
            minHeight: 500,
          }}
        >
          <ReactFlowProvider>
            <div className="absolute inset-0">
              <FlowCanvas
                graphNodes={data.nodes}
                graphEdges={data.edges}
              />
            </div>
          </ReactFlowProvider>
        </div>
      )}
    </div>
  );
}
