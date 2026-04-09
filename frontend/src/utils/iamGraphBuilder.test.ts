import { describe, it, expect, vi } from "vitest";
import { buildIamGraph, getInitialCollapsedIds } from "./iamGraphBuilder";
import type { IamGraphResponse } from "@/types";

function makeResponse(
  overrides: Partial<IamGraphResponse> = {},
): IamGraphResponse {
  return {
    account_id: "123456",
    users: [],
    account_violations: [],
    ...overrides,
  };
}

function makeUser(
  name: string,
  overrides: Partial<IamGraphResponse["users"][0]> = {},
) {
  return {
    name,
    arn: `arn:aws:iam::123456:user/${name}`,
    mfa_enabled: true,
    inline_policies: [],
    attached_policies: [],
    groups: [],
    effective_permissions: {},
    violations: [],
    ...overrides,
  };
}

const noop = vi.fn();
const noopSelect = vi.fn();

describe("buildIamGraph", () => {
  it("always includes account node", () => {
    const resp = makeResponse({
      users: [makeUser("alice")],
    });
    const { nodes } = buildIamGraph(resp, new Set(), noop, noopSelect);
    const acct = nodes.find((n) => n.id === "account");
    expect(acct).toBeDefined();
    expect(acct?.type).toBe("accountNode");
  });

  it("empty response → only account node", () => {
    const resp = makeResponse();
    const { nodes, edges } = buildIamGraph(resp, new Set(), noop, noopSelect);
    expect(nodes).toHaveLength(1);
    expect(nodes[0].id).toBe("account");
    expect(edges).toHaveLength(0);
  });

  it("account node count equals user count", () => {
    const resp = makeResponse({
      users: [makeUser("alice"), makeUser("bob")],
    });
    const { nodes } = buildIamGraph(resp, new Set(), noop, noopSelect);
    const acct = nodes.find((n) => n.id === "account");
    const d = acct!.data as {
      count: number;
      label: string;
    };
    expect(d.count).toBe(2);
    expect(d.label).toBe("users");
  });

  it("creates userNode for each user", () => {
    const resp = makeResponse({
      users: [makeUser("alice"), makeUser("bob")],
    });
    const { nodes } = buildIamGraph(resp, new Set(), noop, noopSelect);
    const userNodes = nodes.filter((n) => n.type === "userNode");
    expect(userNodes).toHaveLength(2);
  });

  it("creates policyNode for inline policies", () => {
    const resp = makeResponse({
      users: [
        makeUser("alice", {
          inline_policies: [{ name: "s3-read", type: "inline" }],
        }),
      ],
    });
    const { nodes } = buildIamGraph(resp, new Set(), noop, noopSelect);
    const polNodes = nodes.filter((n) => n.type === "policyNode");
    expect(polNodes).toHaveLength(1);
    expect((polNodes[0].data as { policyName: string }).policyName).toBe(
      "s3-read",
    );
  });

  it("creates policyNode for managed policies", () => {
    const resp = makeResponse({
      users: [
        makeUser("alice", {
          attached_policies: [
            {
              name: "SecurityAudit",
              arn: "arn:aws:iam::aws:policy/SecurityAudit",
              type: "managed",
            },
          ],
        }),
      ],
    });
    const { nodes } = buildIamGraph(resp, new Set(), noop, noopSelect);
    const polNodes = nodes.filter((n) => n.type === "policyNode");
    expect(polNodes).toHaveLength(1);
    expect((polNodes[0].data as { policyType: string }).policyType).toBe(
      "managed",
    );
  });

  it("creates policyNode for group policies", () => {
    const resp = makeResponse({
      users: [
        makeUser("alice", {
          groups: [
            {
              name: "Devs",
              arn: "arn:aws:iam::123:group/Devs",
              policies: [
                {
                  name: "DevPolicy",
                  type: "inline",
                },
              ],
            },
          ],
        }),
      ],
    });
    const { nodes } = buildIamGraph(resp, new Set(), noop, noopSelect);
    const polNodes = nodes.filter((n) => n.type === "policyNode");
    expect(polNodes).toHaveLength(1);
    expect((polNodes[0].data as { groupName?: string }).groupName).toBe("Devs");
  });

  it("creates serviceNode for permissions", () => {
    const resp = makeResponse({
      users: [
        makeUser("alice", {
          effective_permissions: {
            s3: ["GetObject", "PutObject"],
            ec2: ["*"],
          },
        }),
      ],
    });
    const { nodes } = buildIamGraph(resp, new Set(), noop, noopSelect);
    const svcNodes = nodes.filter((n) => n.type === "serviceNode");
    expect(svcNodes).toHaveLength(2);
  });

  it("violations no longer create checkNodes in graph", () => {
    const resp = makeResponse({
      users: [
        makeUser("alice", {
          violations: [
            {
              check_id: "iam_pwd_max_age",
              status: "alarm",
              severity: "medium" as const,
              reason: "Unused key",
              risk_score: 50,
            },
          ],
        }),
      ],
    });
    const { nodes } = buildIamGraph(resp, new Set(), noop, noopSelect);
    const chkNodes = nodes.filter((n) => n.type === "checkNode");
    expect(chkNodes).toHaveLength(0);
  });

  it("no duplicate node IDs", () => {
    const resp = makeResponse({
      users: [
        makeUser("alice", {
          inline_policies: [{ name: "p1", type: "inline" }],
          effective_permissions: { s3: ["*"] },
          violations: [
            {
              check_id: "iam_root_mfa",
              status: "alarm",
              severity: "high" as const,
              reason: "test",
              risk_score: 80,
            },
          ],
        }),
        makeUser("bob"),
      ],
      account_violations: [
        {
          check_id: "iam_pwd_min_length",
          status: "alarm",
          severity: "critical" as const,
          reason: "root",
          risk_score: 95,
          resource: "arn:aws:iam::123:root",
        },
      ],
    });
    const { nodes } = buildIamGraph(resp, new Set(), noop, noopSelect);
    const ids = nodes.map((n) => n.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it("all edges reference existing nodes", () => {
    const resp = makeResponse({
      users: [
        makeUser("alice", {
          attached_policies: [
            {
              name: "Pol1",
              arn: "arn:aws:iam::aws:policy/P",
              type: "managed",
            },
          ],
          effective_permissions: { iam: ["*"] },
          violations: [
            {
              check_id: "iam_user_mfa",
              status: "alarm",
              severity: "high" as const,
              reason: "test",
              risk_score: 72,
            },
          ],
        }),
      ],
    });
    const { nodes, edges } = buildIamGraph(resp, new Set(), noop, noopSelect);
    const nodeIds = new Set(nodes.map((n) => n.id));
    for (const e of edges) {
      expect(nodeIds.has(e.source)).toBe(true);
      expect(nodeIds.has(e.target)).toBe(true);
    }
  });

  it("collapsed user hides children", () => {
    const resp = makeResponse({
      users: [
        makeUser("alice", {
          inline_policies: [{ name: "p1", type: "inline" }],
          effective_permissions: { s3: ["*"] },
        }),
      ],
    });
    const expanded = buildIamGraph(resp, new Set(), noop, noopSelect);
    const collapsed = buildIamGraph(
      resp,
      new Set(["user-alice"]),
      noop,
      noopSelect,
    );
    const exChildren = expanded.nodes.filter(
      (n) => n.type === "policyNode" || n.type === "serviceNode",
    );
    const colChildren = collapsed.nodes.filter(
      (n) => n.type === "policyNode" || n.type === "serviceNode",
    );
    expect(exChildren.length).toBeGreaterThan(0);
    expect(colChildren).toHaveLength(0);
  });

  it("worstSeverity on user node", () => {
    const resp = makeResponse({
      users: [
        makeUser("alice", {
          violations: [
            {
              check_id: "iam_root_mfa",
              status: "alarm",
              severity: "medium" as const,
              reason: "a",
              risk_score: 40,
            },
            {
              check_id: "iam_pwd_min_length",
              status: "alarm",
              severity: "critical" as const,
              reason: "b",
              risk_score: 95,
            },
          ],
        }),
      ],
    });
    const { nodes } = buildIamGraph(resp, new Set(), noop, noopSelect);
    const userNode = nodes.find((n) => n.type === "userNode");
    const d = userNode!.data as {
      worstSeverity: string;
    };
    expect(d.worstSeverity).toBe("critical");
  });

  it("account violations do NOT create groupNode", () => {
    const resp = makeResponse({
      account_violations: [
        {
          check_id: "iam_root_mfa",
          status: "alarm",
          severity: "critical" as const,
          reason: "Root MFA",
          risk_score: 95,
          resource: "arn:aws:iam::123:root",
        },
      ],
    });
    const { nodes } = buildIamGraph(resp, new Set(), noop, noopSelect);
    expect(nodes.some((n) => n.id === "acct-checks")).toBe(false);
  });

  it("uses smoothstep edges", () => {
    const resp = makeResponse({
      users: [makeUser("alice")],
    });
    const { edges } = buildIamGraph(resp, new Set(), noop, noopSelect);
    for (const e of edges) {
      expect(e.type).toBe("smoothstep");
    }
  });

  it("violations no longer create edges in graph", () => {
    const resp = makeResponse({
      users: [
        makeUser("alice", {
          violations: [
            {
              check_id: "iam_user_mfa",
              status: "alarm",
              severity: "high" as const,
              reason: "test",
              risk_score: 72,
            },
            {
              check_id: "iam_root_access_keys",
              status: "ok",
              severity: "low" as const,
              reason: "fine",
              risk_score: 10,
            },
          ],
        }),
      ],
    });
    const { edges } = buildIamGraph(resp, new Set(), noop, noopSelect);
    const chkEdges = edges.filter((e) => e.target.startsWith("chk-"));
    expect(chkEdges).toHaveLength(0);
  });

  it("user data includes count badges", () => {
    const resp = makeResponse({
      users: [
        makeUser("alice", {
          inline_policies: [{ name: "p1", type: "inline" }],
          attached_policies: [
            {
              name: "p2",
              arn: "arn:a",
              type: "managed",
            },
          ],
          groups: [
            {
              name: "G1",
              arn: "arn:g",
              policies: [{ name: "gp", type: "inline" }],
            },
          ],
          violations: [
            {
              check_id: "iam_pwd_numbers",
              status: "alarm",
              severity: "high" as const,
              reason: "x",
              risk_score: 70,
            },
          ],
        }),
      ],
    });
    const { nodes } = buildIamGraph(resp, new Set(), noop, noopSelect);
    const user = nodes.find((n) => n.type === "userNode");
    const d = user!.data as {
      policyCount: number;
      groupCount: number;
      violationCount: number;
      mfaEnabled: boolean;
    };
    expect(d.policyCount).toBe(3); // 1 inline + 1 managed + 1 group
    expect(d.groupCount).toBe(1);
    expect(d.violationCount).toBe(1);
    expect(d.mfaEnabled).toBe(true);
  });

  it("collapsed account returns only account node", () => {
    const resp = makeResponse({
      users: [
        makeUser("alice", {
          inline_policies: [{ name: "p1", type: "inline" }],
          effective_permissions: { s3: ["*"] },
          violations: [
            {
              check_id: "iam_user_mfa",
              status: "alarm",
              severity: "high" as const,
              reason: "test",
              risk_score: 72,
            },
          ],
        }),
        makeUser("bob"),
      ],
      account_violations: [
        {
          check_id: "iam_root_mfa",
          status: "alarm",
          severity: "critical" as const,
          reason: "Root MFA",
          risk_score: 95,
          resource: "arn:aws:iam::123:root",
        },
      ],
    });
    const { nodes, edges } = buildIamGraph(
      resp,
      new Set(["account"]),
      noop,
      noopSelect,
    );
    expect(nodes).toHaveLength(1);
    expect(nodes[0].id).toBe("account");
    expect(edges).toHaveLength(0);
  });

  it("does NOT create acct-checks groupNode", () => {
    const resp = makeResponse({
      account_violations: [
        {
          check_id: "iam_root_mfa",
          status: "alarm",
          severity: "critical" as const,
          reason: "Root MFA",
          risk_score: 95,
          resource: "arn:aws:iam::123:root",
        },
      ],
    });
    const { nodes } = buildIamGraph(resp, new Set(), noop, noopSelect);
    expect(nodes.some((n) => n.id === "acct-checks")).toBe(false);
  });

  it("does NOT create edges to acct-checks", () => {
    const resp = makeResponse({
      account_violations: [
        {
          check_id: "iam_root_mfa",
          status: "alarm",
          severity: "critical" as const,
          reason: "Root MFA",
          risk_score: 95,
          resource: "arn:aws:iam::123:root",
        },
      ],
    });
    const { edges } = buildIamGraph(resp, new Set(), noop, noopSelect);
    expect(edges.some((e) => e.target === "acct-checks")).toBe(false);
  });

  it("does NOT create check nodes for account violations", () => {
    const resp = makeResponse({
      account_violations: [
        {
          check_id: "iam_root_mfa",
          status: "alarm",
          severity: "critical" as const,
          reason: "Root MFA",
          risk_score: 95,
          resource: "arn:aws:iam::123:root",
        },
      ],
    });
    const { nodes } = buildIamGraph(resp, new Set(), noop, noopSelect);
    expect(nodes.some((n) => n.id === "chk-acct-iam_root_mfa")).toBe(false);
  });
});

describe("getInitialCollapsedIds", () => {
  it("includes account and all user IDs", () => {
    const resp = makeResponse({
      users: [makeUser("alice"), makeUser("bob")],
    });
    const ids = getInitialCollapsedIds(resp);
    expect(ids.has("account")).toBe(true);
    expect(ids.has("user-alice")).toBe(true);
    expect(ids.has("user-bob")).toBe(true);
  });

  it("never includes acct-checks (account checks removed)", () => {
    const resp = makeResponse({
      account_violations: [
        {
          check_id: "iam_root_mfa",
          status: "alarm",
          severity: "critical" as const,
          reason: "Root MFA",
          risk_score: 95,
          resource: "arn:aws:iam::123:root",
        },
      ],
    });
    const ids = getInitialCollapsedIds(resp);
    expect(ids.has("acct-checks")).toBe(false);
  });
});
