import type { Severity, Violation, ViolationStatus } from "@/types";
import type {
  IamNode,
  IamEdge,
  AccountNode,
  UserNode,
  CheckNode,
  PolicyNodeRF,
  ServiceNodeRF,
  PolicyNodeData,
  ServiceNodeData,
  CheckData,
  IamGraphResponse,
  IamGraphUser,
  IamGraphViolation,
} from "@/types/iamGraph";

// --- Layout constants (horizontal tree) ---
const COL1_X = 300;
const COL2_X = 600;
const CHILD_H = 110;
const CHILD_GAP = 14;
const USER_H = 140;
const USER_GAP = 40;
const ACCOUNT_H = 70;

const SEVERITY_RANK: Record<string, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
};

function getWorstSeverity(violations: IamGraphViolation[]): Severity | null {
  let best: Severity | null = null;
  let rank = 0;
  for (const v of violations) {
    const r = SEVERITY_RANK[v.severity] ?? 0;
    if (r > rank) {
      rank = r;
      best = v.severity;
    }
  }
  return best;
}

function toViolation(v: IamGraphViolation, resource: string): Violation {
  return {
    check_id: v.check_id,
    status: v.status as ViolationStatus,
    severity: v.severity,
    reason: v.reason,
    resource,
    domain: "identity",
    compliance: {
      cis_aws: [],
      nist_800_53: [],
      pci_dss: [],
      hipaa: [],
      soc2: [],
    },
    remediation_id: "",
    risk_score: v.risk_score,
  };
}

// --- Child descriptor ---
interface ChildInfo {
  nodeId: string;
  type: "policyNode" | "serviceNode" | "checkNode";
  data: PolicyNodeData | ServiceNodeData | CheckData;
  edgeColor: string;
  animated: boolean;
}

function buildUserChildren(
  user: IamGraphUser,
  onSelect: (v: Violation) => void,
): ChildInfo[] {
  const children: ChildInfo[] = [];
  const uid = user.name;

  // Inline policies
  for (const p of user.inline_policies) {
    children.push({
      nodeId: `pol-${uid}-i-${p.name}`,
      type: "policyNode",
      data: {
        policyName: p.name,
        policyType: "inline",
        resourceName: uid,
      },
      edgeColor: "#3b82f6",
      animated: false,
    });
  }

  // Attached managed policies
  for (const p of user.attached_policies) {
    children.push({
      nodeId: `pol-${uid}-m-${p.name}`,
      type: "policyNode",
      data: {
        policyName: p.name,
        policyType: "managed",
        resourceName: uid,
      },
      edgeColor: "#3b82f6",
      animated: false,
    });
  }

  // Group policies
  for (const g of user.groups) {
    for (const p of g.policies) {
      children.push({
        nodeId: `pol-${uid}-g-${g.name}-${p.name}`,
        type: "policyNode",
        data: {
          policyName: p.name,
          policyType: p.type as "inline" | "managed",
          groupName: g.name,
          resourceName: uid,
        },
        edgeColor: "#3b82f6",
        animated: false,
      });
    }
  }

  // Effective permissions (services)
  const userResources = user.resources ?? {};
  for (const [svc, actions] of Object.entries(user.effective_permissions)) {
    const svcResources = userResources[svc] ?? [];
    children.push({
      nodeId: `svc-${uid}-${svc}`,
      type: "serviceNode",
      data: {
        serviceName: svc,
        actions,
        resourceName: uid,
        resources: svcResources,
      },
      edgeColor: "#14b8a6",
      animated: false,
    });
  }

  return children;
}

export interface IamGraphData {
  nodes: IamNode[];
  edges: IamEdge[];
}

/**
 * Returns a Set of all collapsible node IDs so the
 * graph starts fully collapsed. Users click to expand.
 */
export function getInitialCollapsedIds(
  response: IamGraphResponse,
): Set<string> {
  const ids = new Set<string>();
  ids.add("account");
  for (const user of response.users) {
    ids.add(`user-${user.name}`);
  }
  return ids;
}

export function buildIamGraph(
  response: IamGraphResponse,
  collapsedIds: Set<string>,
  onToggleCollapse: (id: string) => void,
  onSelect: (v: Violation) => void,
): IamGraphData {
  const nodes: IamNode[] = [];
  const edges: IamEdge[] = [];

  const accountCollapsed = collapsedIds.has("account");

  // Pre-compute user blocks (only if account expanded)
  interface Block {
    user: IamGraphUser;
    nodeId: string;
    children: ChildInfo[];
    blockH: number;
  }

  const blocks: Block[] = [];

  if (!accountCollapsed) {
    for (const user of response.users) {
      const nodeId = `user-${user.name}`;
      const collapsed = collapsedIds.has(nodeId);
      const allChildren = buildUserChildren(user, onSelect);
      const visible = collapsed ? [] : allChildren;
      const childrenH =
        visible.length > 0
          ? visible.length * (CHILD_H + CHILD_GAP) - CHILD_GAP
          : 0;
      const blockH = Math.max(USER_H, childrenH);
      blocks.push({
        user,
        nodeId,
        children: visible,
        blockH,
      });
    }
  }

  // Total height
  const allBlocks = blocks.map((b) => b.blockH);
  const totalH = accountCollapsed
    ? ACCOUNT_H
    : allBlocks.reduce((s, h) => s + h, 0) + (allBlocks.length - 1) * USER_GAP;

  // Account node (column 0, vertically centered)
  nodes.push({
    id: "account",
    type: "accountNode",
    position: { x: 0, y: totalH / 2 - ACCOUNT_H / 2 },
    data: {
      count: response.users.length,
      label: "users",
      isCollapsed: accountCollapsed,
      onToggleCollapse,
    },
    draggable: false,
    selectable: false,
  } as AccountNode);

  // If account is collapsed, return only the account node
  if (accountCollapsed) {
    return { nodes, edges };
  }

  // Position user blocks
  let curY = 0;
  for (const block of blocks) {
    const { user, nodeId, children, blockH } = block;
    const collapsed = collapsedIds.has(nodeId);
    const alarms = user.violations.filter((v) => v.status === "alarm");
    const polCount =
      user.inline_policies.length +
      user.attached_policies.length +
      user.groups.reduce((s, g) => s + g.policies.length, 0);

    // User node
    const userY = curY + blockH / 2 - USER_H / 2;
    nodes.push({
      id: nodeId,
      type: "userNode",
      position: { x: COL1_X, y: userY },
      data: {
        userId: user.name,
        username: user.name,
        arn: user.arn,
        worstSeverity: getWorstSeverity(user.violations),
        alarmCount: alarms.length,
        childIds: children.map((c) => c.nodeId),
        isCollapsed: collapsed,
        onToggleCollapse,
        mfaEnabled: user.mfa_enabled,
        policyCount: polCount,
        groupCount: user.groups.length,
        violationCount: user.violations.length,
      },
    } as UserNode);

    edges.push({
      id: `e-acct-${nodeId}`,
      source: "account",
      target: nodeId,
      type: "smoothstep",
      style: { stroke: "#6366f1" },
    } as IamEdge);

    // Position children
    if (children.length > 0) {
      const childrenTotalH =
        children.length * (CHILD_H + CHILD_GAP) - CHILD_GAP;
      const startY = curY + (blockH - childrenTotalH) / 2;

      for (let i = 0; i < children.length; i++) {
        const c = children[i];
        nodes.push({
          id: c.nodeId,
          type: c.type,
          position: {
            x: COL2_X,
            y: startY + i * (CHILD_H + CHILD_GAP),
          },
          data: c.data,
          draggable: false,
          selectable: c.type === "checkNode",
        } as PolicyNodeRF | ServiceNodeRF | CheckNode);

        edges.push({
          id: `e-${nodeId}-${c.nodeId}`,
          source: nodeId,
          target: c.nodeId,
          type: "smoothstep",
          style: { stroke: c.edgeColor },
          animated: c.animated,
        } as IamEdge);
      }
    }

    curY += blockH + USER_GAP;
  }

  return { nodes, edges };
}
