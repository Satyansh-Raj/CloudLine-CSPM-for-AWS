import type { Node, Edge } from "@xyflow/react";
import type { Severity, Violation } from "@/types";

// --- ReactFlow node data ---

export type AccountData = {
  count: number;
  label: string;
  isCollapsed: boolean;
  onToggleCollapse: (id: string) => void;
};

export type GroupData = {
  groupId: string;
  label: string;
  alarmCount: number;
  childIds: string[];
  isCollapsed: boolean;
  onToggleCollapse: (id: string) => void;
};

export type UserData = {
  userId: string;
  username: string;
  arn: string;
  worstSeverity: Severity | null;
  alarmCount: number;
  childIds: string[];
  isCollapsed: boolean;
  onToggleCollapse: (id: string) => void;
  mfaEnabled?: boolean;
  policyCount?: number;
  groupCount?: number;
  violationCount?: number;
};

export type RoleData = UserData;

export type CheckData = {
  checkId: string;
  violation: Violation;
  onSelect: (violation: Violation) => void;
};

export type AccountNode = Node<AccountData, "accountNode">;
export type GroupNode = Node<GroupData, "groupNode">;
export type UserNode = Node<UserData, "userNode">;
export type RoleNode = Node<RoleData, "roleNode">;
export type CheckNode = Node<CheckData, "checkNode">;

export type PolicyNodeData = {
  policyName: string;
  policyType: "inline" | "managed";
  groupName?: string;
  resourceName?: string;
};

export type ServiceNodeData = {
  serviceName: string;
  actions: string[];
  resourceName?: string;
  resources?: string[];
};

export type PolicyNodeRF = Node<
  PolicyNodeData,
  "policyNode"
>;
export type ServiceNodeRF = Node<
  ServiceNodeData,
  "serviceNode"
>;

export type IamNode =
  | AccountNode
  | GroupNode
  | UserNode
  | RoleNode
  | CheckNode
  | PolicyNodeRF
  | ServiceNodeRF;

export type IamEdge = Edge;

// --- API response types (GET /v1/iam/graph) ---

export interface IamGraphPolicy {
  name: string;
  arn?: string;
  type: "inline" | "managed";
}

export interface IamGraphGroup {
  name: string;
  arn: string;
  policies: IamGraphPolicy[];
}

export interface IamGraphViolation {
  check_id: string;
  status: string;
  severity: Severity;
  reason: string;
  risk_score: number;
}

export interface IamGraphAccountViolation
  extends IamGraphViolation {
  resource: string;
}

/** Effective permissions: service → actions list.
 *  ["*"] means full access to that service.
 *  {"*": ["*"]} means full admin access. */
export type EffectivePermissions = Record<
  string,
  string[]
>;

/** Resource ARNs per service from policy documents. */
export type ServiceResources = Record<
  string,
  string[]
>;

export interface IamGraphUser {
  name: string;
  arn: string;
  mfa_enabled: boolean;
  inline_policies: IamGraphPolicy[];
  attached_policies: IamGraphPolicy[];
  groups: IamGraphGroup[];
  effective_permissions: EffectivePermissions;
  resources?: ServiceResources;
  violations: IamGraphViolation[];
}

export interface IamGraphResponse {
  account_id: string;
  users: IamGraphUser[];
  account_violations: IamGraphAccountViolation[];
}
