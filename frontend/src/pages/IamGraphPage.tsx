import "@xyflow/react/dist/style.css";
import { useState, useCallback, useEffect, useMemo } from "react";
import {
  ReactFlow,
  ReactFlowProvider,
  Background,
  useNodesState,
  useEdgesState,
  useReactFlow,
  BackgroundVariant,
} from "@xyflow/react";
import { useIamGraph } from "@/hooks";
import { useAccount } from "@/hooks/useAccount";
import { AccountBadge, EyebrowLabel } from "@/components/shared";
import {
  buildIamGraph,
  getInitialCollapsedIds,
  type IamGraphData,
} from "@/utils/iamGraphBuilder";
import {
  AccountNode,
  GroupNode,
  UserNode,
  RoleNode,
  CheckNode,
  PolicyNode,
  ServiceNode,
} from "@/components/iam";
import { SeverityBadge, StatusBadge } from "@/components/shared";
import { getCheckName } from "@/constants/checkNames";
import { getComplianceMapping } from "@/constants/complianceMappings";
import type { Violation } from "@/types";
import type { IamNode, IamEdge } from "@/types/iamGraph";

// Stable nodeTypes — must be outside component
const nodeTypes = {
  accountNode: AccountNode,
  groupNode: GroupNode,
  userNode: UserNode,
  roleNode: RoleNode,
  checkNode: CheckNode,
  policyNode: PolicyNode,
  serviceNode: ServiceNode,
};

function toggleSet(set: Set<string>, val: string): Set<string> {
  const next = new Set(set);
  if (next.has(val)) next.delete(val);
  else next.add(val);
  return next;
}

// ── Legend ─────────────────────────────────────────

function LegendRow({ color, label }: { color: string; label: string }) {
  return (
    <div className="flex items-center gap-1.5">
      <span className={`w-2.5 h-2.5 rounded-full ${color} shrink-0`} />
      <span className="capitalize">{label}</span>
    </div>
  );
}

function Legend() {
  return (
    <div
      className={[
        "absolute top-3 left-3 z-10 pointer-events-none",
        "bg-lifted-cream/95 dark:bg-[#1c1c1b]/95 backdrop-blur-sm",
        "border border-ghost-cream dark:border-white/5",
        "rounded-hero px-4 py-3 shadow-elev-1",
        "text-[10px] text-slate-gray dark:text-gray-400",
      ].join(" ")}
    >
      <p className="font-semibold text-[9px] uppercase tracking-wider text-slate-gray/70 dark:text-gray-600 mb-2">
        Legend
      </p>
      <div className="space-y-1.5">
        <LegendRow color="bg-ink-black" label="Account" />
        <LegendRow color="bg-slate-gray" label="User" />
        <LegendRow color="bg-dust-taupe" label="Policy" />
        <LegendRow color="bg-slate-gray/60" label="Service" />
        <div className="border-t border-ghost-cream dark:border-white/5 my-1.5" />
        <LegendRow color="bg-red-400" label="Alarm" />
        <LegendRow color="bg-green-400" label="OK" />
      </div>
    </div>
  );
}

// ── Detail Panel ──────────────────────────────────

function ComplianceRow({
  label,
  controls,
}: {
  label: string;
  controls: string[];
}) {
  if (!controls || controls.length === 0) return null;
  return (
    <div>
      <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-gray dark:text-gray-500 mb-1">
        {label}
      </p>
      <div className="flex flex-wrap gap-1">
        {controls.map((c) => (
          <span
            key={c}
            className={[
              "inline-block px-1.5 py-0.5 rounded-pill",
              "bg-ghost-cream dark:bg-white/5",
              "text-xs text-ink-black dark:text-gray-300",
              "border border-ghost-cream dark:border-white/10",
            ].join(" ")}
          >
            {c}
          </span>
        ))}
      </div>
    </div>
  );
}

function DetailPanel({
  violation,
  onClose,
}: {
  violation: Violation;
  onClose: () => void;
}) {
  const apiComp = violation.compliance;
  const hasApiComp = Object.values(apiComp).some((arr) => arr.length > 0);
  const comp = hasApiComp ? apiComp : getComplianceMapping(violation.check_id);

  const hasComp =
    comp &&
    ((comp.cis_aws?.length ?? 0) > 0 ||
      (comp.nist_800_53?.length ?? 0) > 0 ||
      (comp.pci_dss?.length ?? 0) > 0 ||
      (comp.hipaa?.length ?? 0) > 0 ||
      (comp.soc2?.length ?? 0) > 0);

  return (
    <div
      className={[
        "absolute top-0 right-0 w-80 h-full z-10",
        "bg-lifted-cream dark:bg-[#1c1c1b]",
        "border-l border-ghost-cream dark:border-white/5",
        "shadow-elev-2 overflow-y-auto flex flex-col",
      ].join(" ")}
    >
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-3 border-b border-ghost-cream dark:border-white/5">
        <p className="text-sm font-semibold text-ink-black dark:text-white">
          Check Detail
        </p>
        <button
          onClick={onClose}
          className="text-slate-gray hover:text-ink-black dark:hover:text-gray-200 transition-colors"
          aria-label="Close panel"
        >
          <svg
            className="w-4 h-4"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
            viewBox="0 0 24 24"
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              d="M6 18L18 6M6 6l12 12"
            />
          </svg>
        </button>
      </div>

      <div className="flex-1 p-4 space-y-4 overflow-y-auto">
        {/* Check name + ID */}
        <div>
          <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-gray mb-1">
            Check
          </p>
          <p className="text-sm font-medium text-ink-black dark:text-white">
            {getCheckName(violation.check_id)}
          </p>
          <span
            className={[
              "inline-block mt-1 px-1.5 py-0.5 rounded-pill",
              "bg-ghost-cream dark:bg-white/5",
              "text-xs font-mono text-slate-gray dark:text-gray-400",
              "border border-ghost-cream dark:border-white/10",
            ].join(" ")}
          >
            {violation.check_id}
          </span>
        </div>

        {/* Severity + status */}
        <div className="flex gap-2">
          <SeverityBadge severity={violation.severity} />
          <StatusBadge status={violation.status} />
        </div>

        {/* Resource */}
        <div>
          <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-gray mb-1">
            Resource
          </p>
          <p className="text-xs font-mono break-all text-slate-gray dark:text-gray-400">
            {violation.resource}
          </p>
        </div>

        {/* Reason */}
        {violation.reason && (
          <div>
            <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-gray mb-1">
              Reason
            </p>
            <p className="text-xs text-slate-gray dark:text-gray-400">
              {violation.reason}
            </p>
          </div>
        )}

        {/* Risk score */}
        {violation.risk_score !== undefined && (
          <div>
            <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-gray mb-1">
              Risk Score
            </p>
            <div className="flex items-center gap-2">
              <span className="text-2xl font-black text-ink-black dark:text-white">
                {violation.risk_score}
              </span>
              <span className="text-sm text-slate-gray">/ 100</span>
            </div>
            <div className="h-1.5 bg-ghost-cream dark:bg-white/10 rounded-full mt-1 overflow-hidden">
              <div
                className="h-full bg-ink-black dark:bg-canvas-cream rounded-full"
                style={{
                  width: `${violation.risk_score}%`,
                }}
              />
            </div>
          </div>
        )}

        {/* Compliance */}
        {hasComp && (
          <div className="space-y-2">
            <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-gray">
              Compliance
            </p>
            <ComplianceRow label="CIS AWS" controls={comp.cis_aws ?? []} />
            <ComplianceRow
              label="NIST 800-53"
              controls={comp.nist_800_53 ?? []}
            />
            <ComplianceRow label="PCI DSS" controls={comp.pci_dss ?? []} />
            <ComplianceRow label="HIPAA" controls={comp.hipaa ?? []} />
            <ComplianceRow label="SOC 2" controls={comp.soc2 ?? []} />
          </div>
        )}
      </div>
    </div>
  );
}

// ── Flow Canvas ───────────────────────────────────

function FlowCanvas({
  graphData,
  onToggleCollapse,
  onSelect,
}: {
  graphData: IamGraphData | null;
  onToggleCollapse: (id: string) => void;
  onSelect: (v: Violation) => void;
}) {
  const [nodes, setNodes, onNodesChange] = useNodesState<IamNode>([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState<IamEdge>([]);
  const { fitView } = useReactFlow();

  useEffect(() => {
    if (!graphData) return;
    setNodes(graphData.nodes);
    setEdges(graphData.edges);
    const t = setTimeout(() => fitView({ duration: 400 }), 50);
    return () => clearTimeout(t);
  }, [graphData, setNodes, setEdges, fitView]);

  const handleNodeClick = useCallback(
    (_: React.MouseEvent, node: IamNode) => {
      if (
        node.type === "accountNode" ||
        node.type === "userNode" ||
        node.type === "groupNode"
      ) {
        onToggleCollapse(node.id);
      } else if (node.type === "checkNode") {
        const v = (node.data as { violation: Violation }).violation;
        onSelect(v);
      }
    },
    [onToggleCollapse, onSelect],
  );

  return (
    <ReactFlow
      nodes={nodes}
      edges={edges}
      onNodesChange={onNodesChange}
      onEdgesChange={onEdgesChange}
      onNodeClick={handleNodeClick}
      nodeTypes={nodeTypes}
      nodesDraggable={false}
      fitView
      minZoom={0.1}
      maxZoom={2}
      className="bg-transparent"
    >
      <Background
        variant={BackgroundVariant.Dots}
        gap={20}
        color="#E8E2DA"
        className="dark:opacity-20"
      />
    </ReactFlow>
  );
}

// ── Main Page ─────────────────────────────────────

export default function IamGraphPage() {
  const [collapsedIds, setCollapsedIds] = useState(() => new Set<string>());
  const [initialized, setInitialized] = useState(false);
  const [selectedViolation, setSelectedViolation] = useState<Violation | null>(
    null,
  );
  const [isFullscreen, setIsFullscreen] = useState(false);
  const [search, setSearch] = useState("");

  const { selectedAccount } = useAccount();
  const accountId = selectedAccount || undefined;
  const { data: apiData, isLoading, isError } = useIamGraph(accountId);

  // Collapse all nodes synchronously on first data load
  // (React 18 pattern: set state during render to avoid
  // a one-frame flash of the fully-expanded tree)
  if (apiData && !initialized) {
    setCollapsedIds(getInitialCollapsedIds(apiData));
    setInitialized(true);
  }

  const onToggleCollapse = useCallback((id: string) => {
    setCollapsedIds((prev) => toggleSet(prev, id));
  }, []);

  const onSelect = useCallback((v: Violation) => {
    setSelectedViolation(v);
  }, []);

  // Filter users by search query
  const filteredResponse = useMemo(() => {
    if (!apiData) return null;
    if (!search.trim()) return apiData;
    const q = search.toLowerCase();
    return {
      ...apiData,
      users: apiData.users.filter(
        (u) =>
          u.name.toLowerCase().includes(q) || u.arn.toLowerCase().includes(q),
      ),
    };
  }, [apiData, search]);

  const graphData = useMemo(() => {
    if (!filteredResponse) return null;
    return buildIamGraph(filteredResponse, collapsedIds, onToggleCollapse);
  }, [filteredResponse, collapsedIds, onToggleCollapse]);

  const hasData = !!apiData && apiData.users.length > 0;

  const noMatches =
    hasData && filteredResponse !== null && filteredResponse.users.length === 0;

  return (
    <div
      className={
        isFullscreen
          ? "fixed inset-0 z-50 bg-canvas-cream dark:bg-ink-black flex flex-col"
          : "space-y-4"
      }
    >
      {/* Header */}
      <div
        className={
          isFullscreen
            ? "flex items-center justify-between px-4 py-2 border-b border-ghost-cream dark:border-white/5"
            : ""
        }
      >
        <div>
          {!isFullscreen && (
            <EyebrowLabel className="mb-1">IAM Permissions</EyebrowLabel>
          )}
          <div className="flex items-baseline gap-3">
            <h2 className="text-xl font-bold text-ink-black dark:text-white tracking-tight">
              IAM Graph
            </h2>
            {!isFullscreen && <AccountBadge />}
          </div>
          {!isFullscreen && (
            <p className="text-sm text-slate-gray dark:text-gray-400 mt-0.5">
              IAM permission surface — users, policies, effective permissions
            </p>
          )}
        </div>
        {isFullscreen && (
          <button
            onClick={() => setIsFullscreen(false)}
            className={[
              "px-3 py-1.5 text-xs font-medium rounded-btn",
              "border border-ghost-cream dark:border-white/10",
              "text-slate-gray dark:text-gray-400",
              "hover:bg-ghost-cream dark:hover:bg-white/5 transition-colors",
            ].join(" ")}
            aria-label="Exit fullscreen"
          >
            Exit Fullscreen
          </button>
        )}
      </div>

      {/* Filter bar */}
      <div
        className={[
          "bg-lifted-cream dark:bg-[#1c1c1b] border border-ghost-cream",
          "dark:border-white/5 rounded-hero p-4 shadow-elev-1",
          isFullscreen ? "mx-4" : "",
        ].join(" ")}
      >
        <div className="flex items-center gap-3">
          {/* Search */}
          <input
            type="text"
            placeholder="Search users…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className={[
              "flex-1 min-w-[180px] px-3 py-1.5 text-sm",
              "bg-canvas-cream dark:bg-white/5",
              "border border-ghost-cream dark:border-white/10",
              "rounded-pill text-ink-black dark:text-gray-100",
              "placeholder-slate-gray dark:placeholder-gray-600",
              "outline-none focus:ring-2 focus:ring-ink-black/20",
            ].join(" ")}
          />

          {/* Fullscreen toggle */}
          {!isFullscreen && (
            <button
              onClick={() => setIsFullscreen(true)}
              className={[
                "px-3 py-1.5 text-xs font-medium rounded-btn",
                "border border-ghost-cream dark:border-white/10",
                "text-slate-gray dark:text-gray-400",
                "hover:bg-ghost-cream dark:hover:bg-white/5",
                "transition-colors",
              ].join(" ")}
              aria-label="Enter fullscreen"
            >
              Fullscreen
            </button>
          )}
        </div>
      </div>

      {/* Canvas */}
      <div
        className={[
          "relative overflow-hidden",
          isFullscreen
            ? "flex-1"
            : "rounded-hero border border-ghost-cream dark:border-white/5 bg-canvas-cream dark:bg-ink-black",
        ].join(" ")}
        style={
          isFullscreen
            ? undefined
            : {
                height: "calc(100vh - 280px)",
                minHeight: 500,
              }
        }
      >
        {/* Loading skeleton */}
        {isLoading && (
          <div className="absolute inset-0 flex items-center justify-center animate-pulse">
            <div className="space-y-3 w-full px-8">
              {Array.from({ length: 3 }).map((_, i) => (
                <div
                  key={i}
                  className="h-12 bg-ghost-cream dark:bg-white/5 rounded-hero"
                />
              ))}
            </div>
          </div>
        )}

        {/* Error */}
        {isError && !isLoading && (
          <div className="absolute inset-0 flex items-center justify-center p-8">
            <div className="bg-red-50 dark:bg-red-500/5 border border-red-200 dark:border-red-500/20 rounded-hero p-6 max-w-sm text-center">
              <p className="text-sm font-semibold text-red-700 dark:text-red-400 mb-1">
                Failed to load IAM data
              </p>
              <p className="text-xs text-red-500 dark:text-red-500/70">
                Check that the backend is running and retry.
              </p>
            </div>
          </div>
        )}

        {/* Empty — no data */}
        {!isLoading && !isError && !hasData && (
          <div className="absolute inset-0 flex flex-col items-center justify-center gap-3 p-8">
            <svg
              className="w-12 h-12 text-ghost-cream dark:text-gray-700"
              fill="none"
              stroke="currentColor"
              strokeWidth="1.2"
              viewBox="0 0 24 24"
            >
              <circle cx="12" cy="12" r="10" />
              <path strokeLinecap="round" d="M8 12h8M12 8v8" />
            </svg>
            <p className="text-sm font-medium text-slate-gray dark:text-gray-400">
              No IAM data — run a scan first
            </p>
            <p className="text-xs text-slate-gray/70 dark:text-gray-600 text-center max-w-xs">
              Trigger a scan to populate IAM checks and see the permission graph
              here.
            </p>
          </div>
        )}

        {/* React Flow canvas */}
        {!isLoading && !isError && hasData && (
          <ReactFlowProvider>
            <div className="absolute inset-0">
              <FlowCanvas
                graphData={graphData}
                onToggleCollapse={onToggleCollapse}
                onSelect={onSelect}
              />
            </div>

            {/* No-matches overlay */}
            {noMatches && (
              <div className="absolute inset-0 flex items-center justify-center bg-canvas-cream/80 dark:bg-ink-black/80">
                <p className="text-sm text-slate-gray dark:text-gray-400">
                  No users match your search
                </p>
              </div>
            )}

            {/* Legend */}
            <Legend />

            {/* Detail panel */}
            {selectedViolation && (
              <DetailPanel
                violation={selectedViolation}
                onClose={() => setSelectedViolation(null)}
              />
            )}
          </ReactFlowProvider>
        )}
      </div>
    </div>
  );
}
