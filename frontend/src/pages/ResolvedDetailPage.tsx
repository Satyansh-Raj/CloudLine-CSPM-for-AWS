import { useNavigate, useParams, useLocation } from "react-router-dom";
import { useViolations } from "@/hooks";
import {
  SeverityBadge,
  RiskScoreMeter,
  ComplianceSection,
  EyebrowLabel,
  GhostHeadline,
} from "@/components/shared";
import { getCheckName } from "@/constants/checkNames";
import { getComplianceMapping } from "@/constants/complianceMappings";
import IssueHistoryChart from "@/components/IssueHistoryChart";
import { fromResolvedResource } from "@/utils/violationUrl";
import type { Violation, StatusHistoryEntry } from "@/types";

/* ---- local helpers ---- */

function buildHistory(v: Violation): StatusHistoryEntry[] {
  if (v.status_history && v.status_history.length > 0) {
    return v.status_history;
  }
  const history: StatusHistoryEntry[] = [];
  if (v.first_detected) {
    history.push({
      status: v.previous_status ?? "alarm",
      timestamp: v.first_detected,
    });
  }
  if (v.resolved_at) {
    history.push({
      status: "ok",
      timestamp: v.resolved_at,
    });
  }
  return history;
}

function formatTimestamp(iso?: string): string {
  if (!iso) return "—";
  try {
    return new Date(iso).toLocaleString();
  } catch {
    return iso;
  }
}

/* ---- main page ---- */

export default function ResolvedDetailPage() {
  const navigate = useNavigate();
  const { checkId = "", resource: encodedResource = "" } = useParams();
  const { state } = useLocation();

  const resource = fromResolvedResource(encodedResource);

  const stateViolation = state?.violation as Violation | undefined;
  const { data } = useViolations({ status: "ok" });
  const freshViolation = data?.find(
    (v) => v.check_id === checkId && v.resource === resource,
  );
  const violation: Violation | undefined = freshViolation ?? stateViolation;

  const comp = violation
    ? violation.compliance && Object.keys(violation.compliance).length > 0
      ? violation.compliance
      : getComplianceMapping(violation.check_id)
    : null;

  const hasCompliance =
    comp &&
    ((comp.cis_aws?.length ?? 0) > 0 ||
      (comp.nist_800_53?.length ?? 0) > 0 ||
      (comp.pci_dss?.length ?? 0) > 0 ||
      (comp.hipaa?.length ?? 0) > 0 ||
      (comp.soc2?.length ?? 0) > 0);

  return (
    <div data-testid="resolved-detail-page" className="space-y-5">
      {/* Back */}
      <button
        onClick={() => navigate(-1)}
        className="flex items-center gap-1.5 text-sm text-slate-gray hover:text-ink-black dark:hover:text-canvas-cream transition-colors"
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
            strokeWidth={2}
            d="M15 19l-7-7 7-7"
          />
        </svg>
        Back
      </button>

      {!violation ? (
        <div className="bg-lifted-cream dark:bg-ink-black border border-ghost-cream dark:border-white/5 rounded-hero p-12 text-center shadow-elev-1">
          <div className="w-10 h-10 rounded-hero bg-ghost-cream dark:bg-white/5 flex items-center justify-center mx-auto mb-3">
            <svg
              className="w-5 h-5 text-slate-gray"
              fill="none"
              stroke="currentColor"
              viewBox="0 0 24 24"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={1.5}
                d="M9.172 16.172a4 4 0 015.656 0M9 10h.01M15 10h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"
              />
            </svg>
          </div>
          <p className="text-sm font-medium text-ink-black dark:text-canvas-cream">
            Violation not found
          </p>
          <p className="text-xs text-slate-gray mt-1">
            It may have been resolved or the URL is incorrect.
          </p>
        </div>
      ) : (
        <>
          {/* Header card */}
          <div className="relative overflow-hidden bg-lifted-cream dark:bg-ink-black border border-ghost-cream dark:border-white/5 rounded-hero px-6 py-5 shadow-elev-1">
            <GhostHeadline>DONE</GhostHeadline>
            <img
              src="/resolved.png"
              alt="Resolved"
              className="absolute -top-[0.85rem] right-[5.75rem] w-36 h-36 object-contain"
              style={{ transform: "rotate(-30deg)" }}
            />
            <div className="flex items-center gap-2 flex-wrap mb-2">
              <SeverityBadge severity={violation.severity} />
              <span className="inline-flex items-center text-xs font-medium px-2.5 py-0.5 rounded-pill bg-green-100 dark:bg-green-500/20 text-green-700 dark:text-green-400">
                Resolved
              </span>
              <span className="ml-auto text-[10px] font-mono text-slate-gray/70">
                {violation.check_id}
              </span>
            </div>
            <EyebrowLabel>Resolved Issue</EyebrowLabel>
            <h2 className="text-xl font-bold text-ink-black dark:text-canvas-cream tracking-tight mt-1">
              {getCheckName(violation.check_id)}
            </h2>
            {violation.domain && (
              <p className="text-xs text-slate-gray mt-1 capitalize">
                {violation.domain.replace(/_/g, " ")}
              </p>
            )}
          </div>

          {/* Details grid */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
            {/* Issue details — 2/3 */}
            <div className="lg:col-span-2 bg-lifted-cream dark:bg-ink-black border border-ghost-cream dark:border-white/5 rounded-hero px-6 py-5 shadow-elev-1 flex flex-col">
              <div className="space-y-4">
                <h3 className="text-[10px] font-semibold uppercase tracking-widest text-slate-gray">
                  Issue Details
                </h3>

                <div>
                  <p className="text-xs text-slate-gray/70 mb-0.5">Resource</p>
                  <p className="text-sm font-mono text-ink-black dark:text-canvas-cream break-all">
                    {violation.resource || "N/A"}
                  </p>
                </div>

                <div>
                  <p className="text-xs text-slate-gray/70 mb-0.5">Reason</p>
                  <p className="text-sm text-ink-black dark:text-canvas-cream leading-relaxed">
                    {violation.reason || "No reason provided"}
                  </p>
                </div>
              </div>

              {/* Timestamps */}
              <div className="flex flex-wrap gap-8 pt-3 mt-auto border-t border-ghost-cream dark:border-white/5">
                {violation.first_detected && (
                  <div>
                    <p className="text-xs text-slate-gray/70 mb-0.5">
                      First Detected
                    </p>
                    <p className="text-xs text-ink-black dark:text-canvas-cream">
                      {formatTimestamp(violation.first_detected)}
                    </p>
                  </div>
                )}
                {violation.resolved_at && (
                  <div>
                    <p className="text-xs text-slate-gray/70 mb-0.5">
                      Resolved At
                    </p>
                    <p className="text-xs text-green-600 dark:text-green-400 font-medium">
                      {formatTimestamp(violation.resolved_at)}
                    </p>
                  </div>
                )}
                {violation.last_evaluated && (
                  <div>
                    <p className="text-xs text-slate-gray/70 mb-0.5">
                      Last Evaluated
                    </p>
                    <p className="text-xs text-ink-black dark:text-canvas-cream">
                      {formatTimestamp(violation.last_evaluated)}
                    </p>
                  </div>
                )}
              </div>
            </div>

            {/* Sidebar: risk score + regression + compliance */}
            <div className="space-y-4">
              {violation.risk_score !== undefined && (
                <RiskScoreMeter score={violation.risk_score} />
              )}

              {/* Regression count */}
              <div className="bg-lifted-cream dark:bg-ink-black border border-ghost-cream dark:border-white/5 rounded-hero px-5 py-4 shadow-elev-1">
                <p className="text-xs font-semibold uppercase tracking-widest text-slate-gray mb-2">
                  Regressions
                </p>
                <p className="text-2xl font-black text-ink-black dark:text-canvas-cream">
                  {violation.regression_count ?? 0}
                </p>
                <p className="text-[10px] text-slate-gray mt-1">
                  Times this issue reappeared after resolution
                </p>
              </div>

              {hasCompliance && comp && (
                <div className="bg-lifted-cream dark:bg-ink-black border border-ghost-cream dark:border-white/5 rounded-hero px-5 py-4 shadow-elev-1 space-y-3">
                  <h3 className="text-[10px] font-semibold uppercase tracking-widest text-slate-gray">
                    Compliance
                  </h3>
                  <ComplianceSection
                    label="CIS AWS Foundations Benchmark v1.5.0"
                    controls={comp.cis_aws ?? []}
                  />
                  <ComplianceSection
                    label="NIST 800-53"
                    controls={comp.nist_800_53 ?? []}
                  />
                  <ComplianceSection
                    label="PCI DSS v4.0"
                    controls={comp.pci_dss ?? []}
                  />
                  <ComplianceSection
                    label="HIPAA"
                    controls={comp.hipaa ?? []}
                  />
                  <ComplianceSection label="SOC 2" controls={comp.soc2 ?? []} />
                </div>
              )}
            </div>
          </div>

          {/* Issue History Chart */}
          <div className="bg-lifted-cream dark:bg-ink-black border border-ghost-cream dark:border-white/5 rounded-hero px-6 py-5 shadow-elev-1">
            <IssueHistoryChart statusHistory={buildHistory(violation)} />
          </div>
        </>
      )}
    </div>
  );
}
