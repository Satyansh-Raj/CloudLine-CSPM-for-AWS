import type {
  Severity,
  Violation,
  ViolationStatus,
} from "@/types";
import type {
  IamNode,
  IamEdge,
  AccountNode,
  UserNode,
  CheckNode,
  PolicyNodeRF,
  ServiceNodeRF,
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

function getWorstSeverity(
  violations: IamGraphViolation[],
): Severity | null {
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

function toViolation(
  v: IamGraphViolation,
  resource: string,
): Violation {
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
  data: Record<string, unknown>;
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
        },
        edgeColor: "#3b82f6",
        animated: false,
      });
    }
  }

  // Effective permissions (services)
  for (const [svc, actions] of Object.entries(
    user.effective_permissions,
  )) {
    children.push({
      nodeId: `svc-${uid}-${svc}`,
      type: "serviceNode",
      data: { serviceName: svc, actions },
      edgeColor: "#14b8a6",
      animated: false,
    });
  }

  // Violations
  for (const v of user.violations) {
    const isAlarm = v.status === "alarm";
    children.push({
      nodeId: `chk-${uid}-${v.check_id}`,
      type: "checkNode",
      data: {
        checkId: v.check_id,
        violation: toViolation(v, user.arn),
        onSelect,
      },
      edgeColor: isAlarm ? "#ef4444" : "#22c55e",
      animated: isAlarm,
    });
  }

  return children;
}

export interface IamGraphData {
  nodes: IamNode[];
  edges: IamEdge[];
}

export function buildIamGraph(
  response: IamGraphResponse,
  collapsedIds: Set<string>,
  onToggleCollapse: (id: string) => void,
  onSelect: (v: Violation) => void,
): IamGraphData {
  const nodes: IamNode[] = [];
  const edges: IamEdge[] = [];

  // Pre-compute user blocks
  interface Block {
    user: IamGraphUser;
    nodeId: string;
    children: ChildInfo[];
    blockH: number;
  }

  const blocks: Block[] = [];

  for (const user of response.users) {
    const nodeId = `user-${user.name}`;
    const collapsed = collapsedIds.has(nodeId);
    const allChildren = buildUserChildren(
      user,
      onSelect,
    );
    const visible = collapsed ? [] : allChildren;
    const childrenH =
      visible.length > 0
        ? visible.length * (CHILD_H + CHILD_GAP) -
          CHILD_GAP
        : 0;
    const blockH = Math.max(USER_H, childrenH);
    blocks.push({
      user,
      nodeId,
      children: visible,
      blockH,
    });
  }

  // Account-level violations as a pseudo-block
  const acctViols = response.account_violations;
  const acctChildren: ChildInfo[] = [];
  for (const v of acctViols) {
    const isAlarm = v.status === "alarm";
    acctChildren.push({
      nodeId: `chk-acct-${v.check_id}`,
      type: "checkNode",
      data: {
        checkId: v.check_id,
        violation: toViolation(v, v.resource),
        onSelect,
      },
      edgeColor: isAlarm ? "#ef4444" : "#22c55e",
      animated: isAlarm,
    });
  }

  const acctBlockNodeId = "acct-checks";
  const acctCollapsed =
    collapsedIds.has(acctBlockNodeId);
  const acctVisible = acctCollapsed
    ? []
    : acctChildren;
  const acctChildrenH =
    acctVisible.length > 0
      ? acctVisible.length * (CHILD_H + CHILD_GAP) -
        CHILD_GAP
      : 0;
  const acctBlockH =
    acctViols.length > 0
      ? Math.max(USER_H, acctChildrenH)
      : 0;

  // Total height
  const allBlocks = [
    ...blocks.map((b) => b.blockH),
    ...(acctBlockH > 0 ? [acctBlockH] : []),
  ];
  const totalH =
    allBlocks.reduce((s, h) => s + h, 0) +
    (allBlocks.length - 1) * USER_GAP;

  // Account node (column 0, vertically centered)
  nodes.push({
    id: "account",
    type: "accountNode",
    position: { x: 0, y: totalH / 2 - ACCOUNT_H / 2 },
    data: {
      count: response.users.length,
      label: "users",
    },
    draggable: false,
    selectable: false,
  } as AccountNode);

  // Position user blocks
  let curY = 0;
  for (const block of blocks) {
    const {
      user,
      nodeId,
      children,
      blockH,
    } = block;
    const collapsed = collapsedIds.has(nodeId);
    const alarms = user.violations.filter(
      (v) => v.status === "alarm",
    );
    const polCount =
      user.inline_policies.length +
      user.attached_policies.length +
      user.groups.reduce(
        (s, g) => s + g.policies.length,
        0,
      );

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
        worstSeverity: getWorstSeverity(
          user.violations,
        ),
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
        children.length * (CHILD_H + CHILD_GAP) -
        CHILD_GAP;
      const startY =
        curY + (blockH - childrenTotalH) / 2;

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

  // Account-level violations block
  if (acctViols.length > 0) {
    const acctY =
      curY + acctBlockH / 2 - USER_H / 2;
    const acctAlarms = acctViols.filter(
      (v) => v.status === "alarm",
    );

    nodes.push({
      id: acctBlockNodeId,
      type: "groupNode",
      position: { x: COL1_X, y: acctY },
      data: {
        groupId: "account-checks",
        label: "Account Checks",
        alarmCount: acctAlarms.length,
        childIds: acctVisible.map((c) => c.nodeId),
        isCollapsed: acctCollapsed,
        onToggleCollapse,
      },
    } as IamNode);

    edges.push({
      id: `e-acct-${acctBlockNodeId}`,
      source: "account",
      target: acctBlockNodeId,
      type: "smoothstep",
      style: { stroke: "#6366f1" },
    } as IamEdge);

    if (acctVisible.length > 0) {
      const startY =
        curY +
        (acctBlockH - acctChildrenH) / 2;
      for (let i = 0; i < acctVisible.length; i++) {
        const c = acctVisible[i];
        nodes.push({
          id: c.nodeId,
          type: c.type,
          position: {
            x: COL2_X,
            y:
              startY +
              i * (CHILD_H + CHILD_GAP),
          },
          data: c.data,
          draggable: false,
          selectable: true,
        } as CheckNode);

        edges.push({
          id: `e-${acctBlockNodeId}-${c.nodeId}`,
          source: acctBlockNodeId,
          target: c.nodeId,
          type: "smoothstep",
          style: { stroke: c.edgeColor },
          animated: c.animated,
        } as IamEdge);
      }
    }
  }

  return { nodes, edges };
}
