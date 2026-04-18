import { useState, useMemo } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  getPolicies,
  getPolicySource,
  createPolicy,
  createRawPolicy,
  deletePolicy,
  type CreatePolicyRequest,
  type CreateRawPolicyRequest,
  type PolicyInfo,
} from "@/api/policies";
import { getCheckName } from "@/constants/checkNames";
import SeverityBadge from "@/components/shared/SeverityBadge";
import { EyebrowLabel } from "@/components/shared";

const DOMAINS = [
  "identity",
  "compute",
  "data_protection",
  "network",
  "logging_monitoring",
  "detection",
] as const;

const SEVERITIES = ["critical", "high", "medium", "low"] as const;

const DOMAIN_LABELS: Record<string, string> = {
  identity: "Identity & Access",
  compute: "Compute",
  data_protection: "Data Protection",
  network: "Network",
  logging_monitoring: "Logging & Monitoring",
  detection: "Detection",
};

/** Derive a short service title from a check_id. */
function getServiceTitle(checkId: string): string {
  const TITLE_MAP: Record<string, string> = {
    iam: "IAM",
    ec2: "EC2",
    s3: "S3",
    rds: "RDS",
    db: "Database",
    vpc: "VPC",
    kms: "KMS",
    ebs: "EBS",
    elb: "ELB",
    alb: "ALB",
    nlb: "NLB",
    cdn: "CloudFront",
    apigw: "API Gateway",
    lambda: "Lambda",
    cognito: "Cognito",
    cloudtrail: "CloudTrail",
    cloudwatch: "CloudWatch",
    guardduty: "GuardDuty",
    config: "Config",
    secretsmanager: "Secrets Manager",
    backup: "Backup",
    dynamodb: "DynamoDB",
    ecs: "ECS",
    eks: "EKS",
    ecr: "ECR",
    sns: "SNS",
    sqs: "SQS",
    storage: "Storage",
    serverless: "Serverless",
    awssec: "Security Hub",
    network: "Network",
  };
  const prefix = checkId.split("_")[0];
  return TITLE_MAP[prefix] ?? prefix.toUpperCase();
}

const EMPTY_FORM: CreatePolicyRequest = {
  check_id: "",
  name: "",
  domain: "",
  severity: "",
  description: "",
  input_field: "",
  resource_path: "",
  condition_field: "",
  condition_value: "",
  compliance_cis: "",
  compliance_nist: "",
  compliance_pci: "",
  remediation_id: "",
};

const INPUT_FIELD_MAP: Record<string, string> = {
  iam: "input.iam",
  s3: "input.s3",
  ec2: "input.ec2",
  rds: "input.rds",
  cloudtrail: "input.cloudtrail",
  lambda: "input.lambda_functions",
  vpc: "input.vpc",
  guardduty: "input.guardduty",
  config: "input.config",
  cloudwatch: "input.cloudwatch",
  kms: "input.kms",
  ebs: "input.ebs",
  backup: "input.backup",
  secretsmanager: "input.secretsmanager",
};

function generateRegoPreview(f: CreatePolicyRequest): string {
  if (!f.check_id || !f.domain || !f.severity) return "";
  const inputPath =
    INPUT_FIELD_MAP[f.input_field] ?? `input.${f.input_field || "service"}`;
  const inputTop = inputPath.replace("input.", "").split(".")[0];
  const slug = f.description
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "_")
    .replace(/^_|_$/g, "");
  const num = f.check_id.includes("_") ? f.check_id.split("_")[1] : "01";
  const pkg = `aws.check_${num}_${slug || "custom"}`;
  const cis = f.compliance_cis ? `"${f.compliance_cis}"` : "";
  const nist = f.compliance_nist ? `"${f.compliance_nist}"` : "";
  const pci = f.compliance_pci ? `"${f.compliance_pci}"` : "";
  const res = f.resource_path || "input.service.items[_]";
  return `package ${pkg}

violations contains result if {
\tresource := ${res}
\tresult := {
\t\t"check_id": "${f.check_id}",
\t\t"status": "alarm",
\t\t"severity": "${f.severity}",
\t\t"reason": "${f.description || "..."}",
\t\t"resource": resource.arn,
\t\t"domain": "${f.domain}",
\t\t"compliance": {
\t\t\t"cis_aws": [${cis}],
\t\t\t"nist_800_53": [${nist}],
\t\t\t"pci_dss": [${pci}],
\t\t},
\t\t"remediation_id": "${f.remediation_id || "REM_..."}",
\t}
}

error contains result if {
\tnot ${inputPath}
\tresult := {
\t\t"check_id": "${f.check_id}",
\t\t"status": "error",
\t\t"severity": "${f.severity}",
\t\t"reason": "${inputTop.toUpperCase()} data missing from input",
\t\t"resource": "",
\t\t"domain": "${f.domain}",
\t}
}`;
}

function getRegoTemplate(domain: string): string {
  const service =
    domain === "data_protection"
      ? "s3"
      : domain === "identity"
        ? "iam"
        : domain === "network"
          ? "vpc"
          : domain === "compute"
            ? "ec2"
            : domain === "logging_monitoring"
              ? "cloudtrail"
              : "service";
  return `package aws.${domain}.${service}

import future.keywords.if
import future.keywords.in

violations contains result if {
\tsome resource in input.${service}.items
\t# Add your condition here
\tresult := {
\t\t"check_id": "custom_01",
\t\t"status": "alarm",
\t\t"severity": "medium",
\t\t"reason": "Description of the violation",
\t\t"resource": resource.arn,
\t\t"domain": "${domain}",
\t\t"service": "${service}",
\t\t"compliance": {},
\t\t"remediation_id": "REM_custom_01",
\t}
}
`;
}

const EMPTY_RAW: CreateRawPolicyRequest = {
  rego_code: "",
  domain: "",
  filename: "",
};

/* ── Domain group header icon ─────────────────── */
function ChevronIcon({ open }: { open: boolean }) {
  return (
    <svg
      className={
        "w-4 h-4 text-slate-gray" +
        " transition-transform duration-200" +
        (open ? " rotate-90" : "")
      }
      fill="none"
      stroke="currentColor"
      viewBox="0 0 24 24"
    >
      <path
        strokeLinecap="round"
        strokeLinejoin="round"
        strokeWidth="2"
        d="M9 5l7 7-7 7"
      />
    </svg>
  );
}

export default function PoliciesPage() {
  const queryClient = useQueryClient();
  const [form, setForm] = useState<CreatePolicyRequest>(EMPTY_FORM);
  const [feedback, setFeedback] = useState<{
    type: "success" | "error";
    message: string;
  } | null>(null);

  /* ── Right-panel state ──────────────────────── */
  const [activeTab, setActiveTab] = useState<"gui" | "code">("gui");
  const [rawForm, setRawForm] = useState<CreateRawPolicyRequest>(EMPTY_RAW);

  /* ── Left-panel state ───────────────────────── */
  const [search, setSearch] = useState("");
  const [domainFilter, setDomainFilter] = useState("");
  const [collapsedDomains, setCollapsedDomains] = useState<Set<string>>(
    new Set(),
  );
  const [expandedSource, setExpandedSource] = useState<string | null>(null);
  const [sourceCache, setSourceCache] = useState<Record<string, string>>({});
  const [sourceLoading, setSourceLoading] = useState(false);

  const {
    data: policies,
    isLoading,
    error,
  } = useQuery({
    queryKey: ["policies"],
    queryFn: getPolicies,
  });

  const createMutation = useMutation({
    mutationFn: createPolicy,
    onSuccess: (res) => {
      queryClient.invalidateQueries({
        queryKey: ["policies"],
      });
      setForm(EMPTY_FORM);
      setFeedback({
        type: "success",
        message: `Policy ${res.check_id} created.`,
      });
    },
    onError: (err: { message?: string }) => {
      setFeedback({
        type: "error",
        message: err.message ?? "Failed to create policy.",
      });
    },
  });

  const deleteMutation = useMutation({
    mutationFn: deletePolicy,
    onSuccess: () => {
      queryClient.invalidateQueries({
        queryKey: ["policies"],
      });
      setFeedback({
        type: "success",
        message: "Policy deleted.",
      });
    },
    onError: (err: { message?: string }) => {
      setFeedback({
        type: "error",
        message: err.message ?? "Failed to delete policy.",
      });
    },
  });

  const rawMutation = useMutation({
    mutationFn: createRawPolicy,
    onSuccess: (res) => {
      queryClient.invalidateQueries({
        queryKey: ["policies"],
      });
      setRawForm(EMPTY_RAW);
      setFeedback({
        type: "success",
        message: `Policy created: ${res.check_ids.join(", ")}`,
      });
    },
    onError: (err: { message?: string }) => {
      setFeedback({
        type: "error",
        message: err.message ?? "Failed to create policy.",
      });
    },
  });

  /* ── Filter + group logic ───────────────────── */
  const filtered = useMemo(() => {
    if (!policies) return [];
    const q = search.toLowerCase();
    return policies.filter((p) => {
      if (domainFilter && p.domain !== domainFilter) return false;
      if (!q) return true;
      return (
        p.check_id.toLowerCase().includes(q) ||
        p.domain.toLowerCase().includes(q) ||
        (p.service ?? "").toLowerCase().includes(q) ||
        getCheckName(p.check_id).toLowerCase().includes(q)
      );
    });
  }, [policies, search, domainFilter]);

  const grouped = useMemo(() => {
    const groups: Record<string, PolicyInfo[]> = {};
    for (const p of filtered) {
      const d = p.domain || "other";
      if (!groups[d]) groups[d] = [];
      groups[d].push(p);
    }
    const ordered: [string, PolicyInfo[]][] = [];
    for (const d of DOMAINS) {
      if (groups[d]) ordered.push([d, groups[d]]);
    }
    for (const d of Object.keys(groups)) {
      if (!DOMAINS.includes(d as (typeof DOMAINS)[number])) {
        ordered.push([d, groups[d]]);
      }
    }
    return ordered;
  }, [filtered]);

  /* ── Handlers ───────────────────────────────── */
  function handleChange(
    e: React.ChangeEvent<
      HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement
    >,
  ) {
    setForm((prev) => ({
      ...prev,
      [e.target.name]: e.target.value,
    }));
  }

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setFeedback(null);
    createMutation.mutate(form);
  }

  function handleDelete(checkId: string) {
    setFeedback(null);
    deleteMutation.mutate(checkId);
  }

  function toggleDomain(domain: string) {
    setCollapsedDomains((prev) => {
      const next = new Set(prev);
      if (next.has(domain)) next.delete(domain);
      else next.add(domain);
      return next;
    });
  }

  async function toggleSource(checkId: string) {
    if (expandedSource === checkId) {
      setExpandedSource(null);
      return;
    }
    setExpandedSource(checkId);
    if (sourceCache[checkId]) return;
    setSourceLoading(true);
    try {
      const res = await getPolicySource(checkId);
      setSourceCache((prev) => ({
        ...prev,
        [checkId]: res.rego_code,
      }));
    } catch {
      setSourceCache((prev) => ({
        ...prev,
        [checkId]: "// Failed to load source code",
      }));
    } finally {
      setSourceLoading(false);
    }
  }

  function handleRawChange(
    e: React.ChangeEvent<
      HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement
    >,
  ) {
    setRawForm((prev) => ({
      ...prev,
      [e.target.name]: e.target.value,
    }));
  }

  function handleRawSubmit(e: React.FormEvent) {
    e.preventDefault();
    setFeedback(null);
    rawMutation.mutate(rawForm);
  }

  function insertTemplate() {
    const domain = rawForm.domain || "identity";
    setRawForm((prev) => ({
      ...prev,
      rego_code: getRegoTemplate(domain),
    }));
  }

  const regoPreview = useMemo(() => generateRegoPreview(form), [form]);

  /* ── Shared styles ──────────────────────────── */
  const inputCls =
    "w-full rounded-pill border border-ghost-cream" +
    " dark:border-white/10 bg-canvas-cream dark:bg-ink-black" +
    " px-3 py-2 text-sm text-ink-black" +
    " dark:text-canvas-cream placeholder-slate-gray/60" +
    " dark:placeholder-slate-gray/40" +
    " focus:outline-none focus:ring-2" +
    " focus:ring-ink-black/20 dark:focus:ring-canvas-cream/20 transition-colors";

  const labelCls = "block text-xs font-medium text-slate-gray mb-1";

  const totalCount = policies?.length ?? 0;
  const filteredCount = filtered.length;
  const showingSubset = totalCount > 0 && filteredCount !== totalCount;

  const panelCls =
    "bg-lifted-cream dark:bg-ink-black border" +
    " border-ghost-cream dark:border-white/5" +
    " rounded-hero p-5 shadow-elev-1";

  return (
    <div className="space-y-4">
      <EyebrowLabel>Policy Editor</EyebrowLabel>
      <h2 className="text-xl font-bold text-ink-black dark:text-canvas-cream tracking-tight -mt-2">
        Rego Policies
      </h2>

      {/* Feedback banner */}
      {feedback && (
        <div
          className={`rounded-hero border p-4 text-sm ${
            feedback.type === "success"
              ? "bg-green-50 dark:bg-green-500/5" +
                " border-green-200" +
                " dark:border-green-500/20" +
                " text-green-700 dark:text-green-400"
              : "bg-red-50 dark:bg-red-500/5" +
                " border-red-200" +
                " dark:border-red-500/20" +
                " text-red-700 dark:text-red-400"
          }`}
        >
          {feedback.message}
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* ── Left: Policy list ──────────────── */}
        <div className={panelCls}>
          {/* Header + count */}
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-semibold text-ink-black dark:text-canvas-cream">
              Existing Policies
            </h3>
            {totalCount > 0 && (
              <span
                className={
                  "px-2.5 py-1 text-xs" +
                  " font-semibold rounded-pill" +
                  " bg-ghost-cream dark:bg-white/5" +
                  " text-ink-black dark:text-canvas-cream" +
                  " border border-ghost-cream dark:border-white/10"
                }
              >
                {showingSubset
                  ? `${filteredCount} / ${totalCount}`
                  : totalCount}
              </span>
            )}
          </div>

          {/* Search + domain filter */}
          <div className="flex gap-2 mb-4">
            <div className="relative flex-1">
              <svg
                className={
                  "absolute left-2.5 top-1/2" +
                  " -translate-y-1/2 w-3.5 h-3.5" +
                  " text-slate-gray/60"
                }
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth="2"
                  d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"
                />
              </svg>
              <input
                type="text"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="Search rules..."
                className={
                  "w-full rounded-pill border" +
                  " border-ghost-cream" +
                  " dark:border-white/10" +
                  " bg-canvas-cream dark:bg-ink-black" +
                  " pl-8 pr-3 py-1.5 text-sm" +
                  " text-ink-black" +
                  " dark:text-canvas-cream" +
                  " placeholder-slate-gray/60" +
                  " focus:outline-none" +
                  " focus:ring-2" +
                  " focus:ring-ink-black/20 dark:focus:ring-canvas-cream/20" +
                  " transition-colors"
                }
              />
            </div>
            <select
              value={domainFilter}
              onChange={(e) => setDomainFilter(e.target.value)}
              className={
                "rounded-pill border" +
                " border-ghost-cream" +
                " dark:border-white/10" +
                " bg-canvas-cream dark:bg-ink-black" +
                " px-2.5 py-1.5 text-sm" +
                " text-ink-black" +
                " dark:text-canvas-cream" +
                " focus:outline-none" +
                " focus:ring-2" +
                " focus:ring-ink-black/20 dark:focus:ring-canvas-cream/20" +
                " transition-colors"
              }
            >
              <option value="">All domains</option>
              {DOMAINS.map((d) => (
                <option key={d} value={d}>
                  {DOMAIN_LABELS[d] ?? d.replace(/_/g, " ")}
                </option>
              ))}
            </select>
            {(search || domainFilter) && (
              <button
                onClick={() => {
                  setSearch("");
                  setDomainFilter("");
                }}
                className={
                  "text-xs text-slate-gray" +
                  " hover:text-ink-black dark:hover:text-canvas-cream" +
                  " hover:underline" +
                  " whitespace-nowrap self-center"
                }
              >
                Clear
              </button>
            )}
          </div>

          {/* Loading skeleton */}
          {isLoading && (
            <div className="animate-pulse space-y-2">
              {Array.from({ length: 6 }).map((_, i) => (
                <div
                  key={i}
                  className="h-16 bg-ghost-cream dark:bg-white/5 rounded-xl"
                />
              ))}
            </div>
          )}

          {/* Error */}
          {error && (
            <p className="text-sm text-red-600 dark:text-red-400">
              Failed to load policies:{" "}
              {(error as { message?: string }).message ?? "Unknown error"}
            </p>
          )}

          {/* Empty states */}
          {policies && policies.length === 0 && (
            <p className="text-sm text-slate-gray">No policies found.</p>
          )}

          {policies && policies.length > 0 && filtered.length === 0 && (
            <p className="text-sm text-slate-gray">
              No policies match your search.
            </p>
          )}

          {/* Grouped policy list */}
          {grouped.length > 0 && (
            <div className="space-y-1 max-h-[80vh] overflow-y-auto pr-1">
              {grouped.map(([domain, domainPolicies]) => {
                const collapsed = collapsedDomains.has(domain);
                return (
                  <div key={domain}>
                    {/* Domain header */}
                    <button
                      onClick={() => toggleDomain(domain)}
                      className={
                        "w-full flex items-center" +
                        " gap-2 px-3 py-2" +
                        " rounded-pill" +
                        " hover:bg-canvas-cream" +
                        " dark:hover:bg-white/[0.03]" +
                        " transition-colors" +
                        " group"
                      }
                    >
                      <ChevronIcon open={!collapsed} />
                      <span
                        className={
                          "text-xs font-semibold" +
                          " uppercase" +
                          " tracking-wider" +
                          " text-slate-gray"
                        }
                      >
                        {DOMAIN_LABELS[domain] ?? domain.replace(/_/g, " ")}
                      </span>
                      <span
                        className={
                          "ml-auto text-[10px]" +
                          " font-medium" +
                          " text-slate-gray/70" +
                          " bg-ghost-cream" +
                          " dark:bg-white/5" +
                          " px-1.5 py-0.5" +
                          " rounded-pill"
                        }
                      >
                        {domainPolicies.length}
                      </span>
                    </button>

                    {/* Rules in domain */}
                    {!collapsed && (
                      <div className="space-y-1 ml-2 mt-1">
                        {domainPolicies.map((p) => (
                          <div key={p.check_id}>
                            {/* Rule card */}
                            <div
                              className={
                                "flex items-center" +
                                " justify-between" +
                                " rounded-hero" +
                                " border" +
                                " border-ghost-cream" +
                                " dark:border-white/5" +
                                " bg-canvas-cream" +
                                " dark:bg-white/[0.02]" +
                                " px-4 py-3"
                              }
                            >
                              <div className="min-w-0 flex-1">
                                <p
                                  className={
                                    "text-sm" +
                                    " font-medium" +
                                    " text-ink-black" +
                                    " dark:text-canvas-cream" +
                                    " truncate"
                                  }
                                >
                                  {getServiceTitle(p.check_id)}
                                </p>
                                <div
                                  className={
                                    "flex" +
                                    " items-center" +
                                    " gap-2 mt-1" +
                                    " flex-wrap"
                                  }
                                >
                                  <SeverityBadge severity={p.severity} />
                                  {p.rule_count > 0 && (
                                    <span
                                      className={
                                        "text-[10px]" +
                                        " text-slate-gray/70" +
                                        " bg-ghost-cream" +
                                        " dark:bg-white/5" +
                                        " px-1.5 py-0.5" +
                                        " rounded-pill"
                                      }
                                    >
                                      {p.rule_count}{" "}
                                      {p.rule_count === 1 ? "rule" : "rules"}
                                    </span>
                                  )}
                                </div>
                              </div>

                              {/* Actions */}
                              <div className="flex items-center gap-1 ml-3 shrink-0">
                                {/* View Source */}
                                <button
                                  onClick={() => toggleSource(p.check_id)}
                                  className={
                                    "p-1.5" +
                                    " rounded-btn" +
                                    " text-slate-gray" +
                                    " hover:text-link-blue" +
                                    " hover:bg-ghost-cream" +
                                    " dark:hover:bg-white/5" +
                                    " transition-colors"
                                  }
                                  title="View source"
                                >
                                  <svg
                                    className="w-4 h-4"
                                    fill="none"
                                    stroke="currentColor"
                                    viewBox="0 0 24 24"
                                  >
                                    <path
                                      strokeLinecap="round"
                                      strokeLinejoin="round"
                                      strokeWidth="1.8"
                                      d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4"
                                    />
                                  </svg>
                                </button>

                                {/* Delete */}
                                <button
                                  onClick={() => handleDelete(p.check_id)}
                                  disabled={deleteMutation.isPending}
                                  className={
                                    "p-1.5" +
                                    " rounded-btn" +
                                    " text-slate-gray" +
                                    " hover:text-red-600" +
                                    " dark:hover:text-red-400" +
                                    " hover:bg-red-50" +
                                    " dark:hover:bg-red-500/10" +
                                    " transition-colors" +
                                    " disabled:opacity-50"
                                  }
                                  title={`Delete ${p.check_id}`}
                                >
                                  <svg
                                    className="w-4 h-4"
                                    fill="none"
                                    stroke="currentColor"
                                    viewBox="0 0 24 24"
                                  >
                                    <path
                                      strokeLinecap="round"
                                      strokeLinejoin="round"
                                      strokeWidth="1.8"
                                      d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"
                                    />
                                  </svg>
                                </button>
                              </div>
                            </div>

                            {/* Source code panel — intentionally dark terminal */}
                            {expandedSource === p.check_id && (
                              <div
                                className={
                                  "mt-1 ml-4" +
                                  " rounded-hero" +
                                  " border" +
                                  " border-ghost-cream" +
                                  " dark:border-white/5" +
                                  " bg-gray-900" +
                                  " dark:bg-black/40" +
                                  " overflow-hidden"
                                }
                              >
                                <div
                                  className={
                                    "flex" +
                                    " items-center" +
                                    " justify-between" +
                                    " px-10 py-1.5" +
                                    " bg-gray-800" +
                                    " dark:bg-white/5" +
                                    " border-b" +
                                    " border-gray-700" +
                                    " dark:border-white/5"
                                  }
                                >
                                  <span
                                    className={
                                      "text-[10px]" +
                                      " font-mono" +
                                      " text-gray-400" +
                                      " dark:text-gray-500"
                                    }
                                  >
                                    {p.filename}
                                  </span>
                                  <button
                                    onClick={() => setExpandedSource(null)}
                                    className={
                                      "text-gray-500" +
                                      " hover:text-gray-300" +
                                      " transition-colors"
                                    }
                                  >
                                    <svg
                                      className="w-3.5 h-3.5"
                                      fill="none"
                                      stroke="currentColor"
                                      viewBox="0 0 24 24"
                                    >
                                      <path
                                        strokeLinecap="round"
                                        strokeLinejoin="round"
                                        strokeWidth="2"
                                        d="M6 18L18 6M6 6l12 12"
                                      />
                                    </svg>
                                  </button>
                                </div>
                                {sourceLoading && !sourceCache[p.check_id] ? (
                                  <div className="px-10 py-3">
                                    <div
                                      className={
                                        "h-3 w-32" +
                                        " bg-gray-700" +
                                        " rounded" +
                                        " animate-pulse"
                                      }
                                    />
                                  </div>
                                ) : (
                                  <pre
                                    className={
                                      "px-10 py-3" +
                                      " text-xs" +
                                      " leading-relaxed" +
                                      " font-mono" +
                                      " text-green-400" +
                                      " dark:text-green-300" +
                                      " overflow-x-auto" +
                                      " max-h-[40vh]" +
                                      " overflow-y-auto"
                                    }
                                  >
                                    {sourceCache[p.check_id] ?? ""}
                                  </pre>
                                )}
                              </div>
                            )}
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* ── Right: Add Policy (tabbed) ────── */}
        <div className={panelCls}>
          <h3 className="text-sm font-semibold text-ink-black dark:text-canvas-cream mb-4">
            Add New Policy
          </h3>

          {/* Tab switcher — pill segment control */}
          <div
            className={
              "inline-flex rounded-pill border" +
              " border-ghost-cream dark:border-white/10" +
              " bg-canvas-cream dark:bg-ink-black" +
              " overflow-hidden p-0.5 gap-0.5 mb-4 w-full"
            }
          >
            <button
              onClick={() => setActiveTab("gui")}
              className={
                "flex-1 px-3 py-1.5 text-xs" +
                " font-semibold transition-colors rounded-pill" +
                (activeTab === "gui"
                  ? " bg-ink-black text-canvas-cream dark:bg-canvas-cream dark:text-ink-black"
                  : " text-slate-gray hover:bg-ghost-cream dark:hover:bg-white/5")
              }
            >
              GUI Builder
            </button>
            <button
              onClick={() => setActiveTab("code")}
              className={
                "flex-1 px-3 py-1.5 text-xs" +
                " font-semibold transition-colors rounded-pill" +
                (activeTab === "code"
                  ? " bg-ink-black text-canvas-cream dark:bg-canvas-cream dark:text-ink-black"
                  : " text-slate-gray hover:bg-ghost-cream dark:hover:bg-white/5")
              }
            >
              Code Editor
            </button>
          </div>

          {/* ── GUI Builder tab ──────────────── */}
          {activeTab === "gui" && (
            <form onSubmit={handleSubmit} className="space-y-3">
              {/* Check ID */}
              <div>
                <label className={labelCls}>Check ID</label>
                <input
                  name="check_id"
                  value={form.check_id}
                  onChange={handleChange}
                  placeholder="s3_21"
                  required
                  className={inputCls}
                />
              </div>

              {/* Name */}
              <div>
                <label className={labelCls}>Name</label>
                <input
                  name="name"
                  value={form.name}
                  onChange={handleChange}
                  placeholder="S3 Versioning Disabled"
                  required
                  className={inputCls}
                />
              </div>

              {/* Domain + Severity */}
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className={labelCls}>Domain</label>
                  <select
                    name="domain"
                    value={form.domain}
                    onChange={handleChange}
                    required
                    className={inputCls}
                  >
                    <option value="">Select...</option>
                    {DOMAINS.map((d) => (
                      <option key={d} value={d}>
                        {DOMAIN_LABELS[d] ?? d.replace(/_/g, " ")}
                      </option>
                    ))}
                  </select>
                </div>
                <div>
                  <label className={labelCls}>Severity</label>
                  <select
                    name="severity"
                    value={form.severity}
                    onChange={handleChange}
                    required
                    className={inputCls}
                  >
                    <option value="">Select...</option>
                    {SEVERITIES.map((s) => (
                      <option key={s} value={s}>
                        {s.charAt(0).toUpperCase() + s.slice(1)}
                      </option>
                    ))}
                  </select>
                </div>
              </div>

              {/* Description */}
              <div>
                <label className={labelCls}>Description</label>
                <textarea
                  name="description"
                  value={form.description}
                  onChange={handleChange}
                  placeholder="Detects S3 buckets without..."
                  required
                  rows={2}
                  className={inputCls}
                />
              </div>

              {/* Input Field + Resource Path */}
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className={labelCls}>Input Field</label>
                  <input
                    name="input_field"
                    value={form.input_field}
                    onChange={handleChange}
                    placeholder="s3"
                    required
                    className={inputCls}
                  />
                </div>
                <div>
                  <label className={labelCls}>Resource Path</label>
                  <input
                    name="resource_path"
                    value={form.resource_path}
                    onChange={handleChange}
                    placeholder="input.s3.buckets[_]"
                    required
                    className={inputCls}
                  />
                </div>
              </div>

              {/* Condition Field + Value */}
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className={labelCls}>Condition Field</label>
                  <input
                    name="condition_field"
                    value={form.condition_field}
                    onChange={handleChange}
                    placeholder="versioning_enabled"
                    required
                    className={inputCls}
                  />
                </div>
                <div>
                  <label className={labelCls}>Condition Value</label>
                  <input
                    name="condition_value"
                    value={form.condition_value}
                    onChange={handleChange}
                    placeholder="false"
                    required
                    className={inputCls}
                  />
                </div>
              </div>

              {/* Compliance */}
              <div className="grid grid-cols-3 gap-3">
                <div>
                  <label className={labelCls}>CIS</label>
                  <input
                    name="compliance_cis"
                    value={form.compliance_cis}
                    onChange={handleChange}
                    placeholder="2.1.3"
                    className={inputCls}
                  />
                </div>
                <div>
                  <label className={labelCls}>NIST</label>
                  <input
                    name="compliance_nist"
                    value={form.compliance_nist}
                    onChange={handleChange}
                    placeholder="SC-28"
                    className={inputCls}
                  />
                </div>
                <div>
                  <label className={labelCls}>PCI</label>
                  <input
                    name="compliance_pci"
                    value={form.compliance_pci}
                    onChange={handleChange}
                    placeholder="3.4"
                    className={inputCls}
                  />
                </div>
              </div>

              {/* Remediation ID */}
              <div>
                <label className={labelCls}>Remediation ID</label>
                <input
                  name="remediation_id"
                  value={form.remediation_id}
                  onChange={handleChange}
                  placeholder="REM_s3_21"
                  className={inputCls}
                />
              </div>

              {/* Rego Preview — intentionally dark terminal */}
              {regoPreview && (
                <div>
                  <label className={labelCls}>Generated Rego Preview</label>
                  <pre
                    className={
                      "rounded-hero border" +
                      " border-ghost-cream dark:border-white/5" +
                      " bg-gray-900 dark:bg-black/40" +
                      " px-4 py-3 text-xs" +
                      " leading-relaxed font-mono" +
                      " text-green-400 dark:text-green-300" +
                      " overflow-x-auto max-h-[30vh] overflow-y-auto"
                    }
                  >
                    {regoPreview}
                  </pre>
                </div>
              )}

              {/* Submit */}
              <button
                type="submit"
                disabled={createMutation.isPending}
                className={
                  "w-full mt-2 px-4 py-2.5" +
                  " rounded-btn text-sm" +
                  " font-medium" +
                  " bg-ink-black text-canvas-cream" +
                  " dark:bg-canvas-cream dark:text-ink-black" +
                  " hover:opacity-90" +
                  " disabled:opacity-50" +
                  " transition-opacity"
                }
              >
                {createMutation.isPending ? "Creating..." : "Create Policy"}
              </button>
            </form>
          )}

          {/* ── Code Editor tab ──────────────── */}
          {activeTab === "code" && (
            <form onSubmit={handleRawSubmit} className="space-y-3">
              {/* Domain + Filename row */}
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className={labelCls}>Domain</label>
                  <select
                    name="domain"
                    value={rawForm.domain}
                    onChange={handleRawChange}
                    required
                    className={inputCls}
                  >
                    <option value="">Select...</option>
                    {DOMAINS.map((d) => (
                      <option key={d} value={d}>
                        {DOMAIN_LABELS[d] ?? d.replace(/_/g, " ")}
                      </option>
                    ))}
                  </select>
                </div>
                <div>
                  <label className={labelCls}>Filename</label>
                  <input
                    name="filename"
                    value={rawForm.filename}
                    onChange={handleRawChange}
                    placeholder="custom_check.rego"
                    required
                    className={inputCls}
                  />
                </div>
              </div>

              {/* Template button */}
              <div className="flex justify-end">
                <button
                  type="button"
                  onClick={insertTemplate}
                  className={
                    "text-xs font-medium" +
                    " text-link-blue" +
                    " hover:underline"
                  }
                >
                  Insert starter template
                </button>
              </div>

              {/* Code textarea — intentionally dark terminal */}
              <div>
                <label className={labelCls}>Rego Policy Code</label>
                <textarea
                  name="rego_code"
                  value={rawForm.rego_code}
                  onChange={handleRawChange}
                  placeholder={
                    "package aws.identity.custom\n\n" +
                    "import future.keywords.if\n" +
                    "import future.keywords.in\n\n" +
                    "violations contains result if {\n" +
                    "\t# your rules here\n" +
                    "}"
                  }
                  required
                  rows={16}
                  spellCheck={false}
                  className={
                    "w-full rounded-hero border" +
                    " border-ghost-cream dark:border-white/5" +
                    " bg-gray-900 dark:bg-black/40" +
                    " px-4 py-3 text-xs" +
                    " leading-relaxed font-mono" +
                    " text-green-400 dark:text-green-300" +
                    " placeholder-gray-600 dark:placeholder-gray-700" +
                    " focus:outline-none focus:ring-2" +
                    " focus:ring-ink-black/20 dark:focus:ring-canvas-cream/20" +
                    " transition-colors resize-y"
                  }
                />
              </div>

              {/* Submit */}
              <button
                type="submit"
                disabled={rawMutation.isPending}
                className={
                  "w-full mt-2 px-4 py-2.5" +
                  " rounded-btn text-sm" +
                  " font-medium" +
                  " bg-ink-black text-canvas-cream" +
                  " dark:bg-canvas-cream dark:text-ink-black" +
                  " hover:opacity-90" +
                  " disabled:opacity-50" +
                  " transition-opacity"
                }
              >
                {rawMutation.isPending ? "Creating..." : "Create Policy"}
              </button>
            </form>
          )}
        </div>
      </div>
    </div>
  );
}
