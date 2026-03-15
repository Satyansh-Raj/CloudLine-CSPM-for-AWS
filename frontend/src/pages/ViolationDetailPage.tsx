import { useNavigate, useParams, useLocation } from "react-router-dom";
import { useViolations } from "@/hooks";
import { SeverityBadge, StatusBadge } from "@/components/shared";
import { getCheckName } from "@/constants/checkNames";
import { getComplianceMapping } from "@/constants/complianceMappings";
import RemediationTabs from "@/components/violations/RemediationTabs";
import { fromViolationResource } from "@/utils/violationUrl";
import type { Violation } from "@/types";

function ComplianceSection({
  label,
  controls,
}: {
  label: string;
  controls: string[];
}) {
  if (controls.length === 0) return null;
  return (
    <div>
      <p className="text-[10px] font-semibold uppercase tracking-wider text-gray-400 dark:text-gray-500 mb-1">
        {label}
      </p>
      <div className="flex flex-wrap gap-1">
        {controls.map((c) => (
          <span
            key={c}
            className="inline-block px-1.5 py-0.5 bg-gray-100 dark:bg-white/5 text-xs rounded text-gray-700 dark:text-gray-300 border border-gray-200 dark:border-white/10"
          >
            {c}
          </span>
        ))}
      </div>
    </div>
  );
}

function RiskScoreMeter({ score }: { score: number }) {
  const { label, bar, text, bg } =
    score >= 76
      ? {
          label: "Critical Risk",
          bar: "bg-red-500",
          text: "text-red-700 dark:text-red-400",
          bg: "bg-red-50 dark:bg-red-500/10 border-red-100 dark:border-red-500/15",
        }
      : score >= 51
      ? {
          label: "High Risk",
          bar: "bg-orange-500",
          text: "text-orange-700 dark:text-orange-400",
          bg: "bg-orange-50 dark:bg-orange-500/10 border-orange-100 dark:border-orange-500/15",
        }
      : score >= 26
      ? {
          label: "Medium Risk",
          bar: "bg-yellow-500",
          text: "text-yellow-700 dark:text-yellow-400",
          bg: "bg-yellow-50 dark:bg-yellow-500/10 border-yellow-100 dark:border-yellow-500/15",
        }
      : {
          label: "Low Risk",
          bar: "bg-green-500",
          text: "text-green-700 dark:text-green-400",
          bg: "bg-green-50 dark:bg-green-500/10 border-green-100 dark:border-green-500/15",
        };

  return (
    <div className={`rounded-2xl border px-5 py-4 shadow-sm ${bg}`}>
      <p className="text-xs font-semibold uppercase tracking-widest text-gray-500 dark:text-gray-400 mb-3">
        Risk Score
      </p>
      <div className="flex items-end gap-2 mb-3">
        <span className={`text-4xl font-black leading-none ${text}`}>
          {score}
        </span>
        <span className="text-sm text-gray-400 dark:text-gray-500 mb-0.5">
          / 100
        </span>
      </div>
      <div className="h-1.5 bg-black/10 dark:bg-white/10 rounded-full overflow-hidden mb-1.5">
        <div
          className={`h-full rounded-full ${bar}`}
          style={{ width: `${score}%` }}
        />
      </div>
      <p className={`text-xs font-semibold ${text}`}>{label}</p>
    </div>
  );
}

export default function ViolationDetailPage() {
  const navigate = useNavigate();
  const { checkId = "", resource: encodedResource = "" } = useParams();
  const { state } = useLocation();

  const resource = fromViolationResource(encodedResource);

  const stateViolation = state?.violation as Violation | undefined;
  const { data } = useViolations({ status: "alarm" });
  const violation: Violation | undefined =
    stateViolation ??
    data?.find(
      (v) => v.check_id === checkId && v.resource === resource,
    );

  const comp = violation
    ? violation.compliance &&
      Object.keys(violation.compliance).length > 0
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
    <div className="space-y-5">
      {/* Logo mark — shifted slightly left */}
      <div className="flex items-center gap-2 ml-[-2px]">
        <div className="w-6 h-6 rounded-md bg-gradient-to-br from-blue-500 to-indigo-600 flex items-center justify-center shrink-0">
          <svg
            className="w-3.5 h-3.5 text-white"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
            viewBox="0 0 24 24"
          >
            <path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5" />
          </svg>
        </div>
        <div>
          <p className="text-xs font-bold tracking-tight text-gray-900 dark:text-white leading-none">
            CloudLine
          </p>
          <p className="text-[9px] text-gray-400 dark:text-gray-600 mt-0.5">
            AWS Security
          </p>
        </div>
      </div>

      {/* Back */}
      <button
        onClick={() => navigate(-1)}
        className="flex items-center gap-1.5 text-sm text-gray-500 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white transition-colors"
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
        <div className="bg-white dark:bg-[#111] border border-gray-100 dark:border-white/5 rounded-2xl p-12 text-center shadow-sm">
          <div className="w-10 h-10 rounded-2xl bg-gray-100 dark:bg-white/5 flex items-center justify-center mx-auto mb-3">
            <svg
              className="w-5 h-5 text-gray-400"
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
          <p className="text-sm font-medium text-gray-700 dark:text-gray-300">
            Violation not found
          </p>
          <p className="text-xs text-gray-400 dark:text-gray-600 mt-1">
            It may have been resolved or the URL is incorrect.
          </p>
        </div>
      ) : (
        <>
          {/* Header card */}
          <div className="bg-white dark:bg-[#111] border border-gray-100 dark:border-white/5 rounded-2xl px-6 py-5 shadow-sm">
            <div className="flex items-center gap-2 flex-wrap mb-2">
              <SeverityBadge severity={violation.severity} />
              <StatusBadge status={violation.status} />
              <span className="ml-auto text-[10px] font-mono text-gray-400 dark:text-gray-600">
                {violation.check_id}
              </span>
            </div>
            <h2 className="text-xl font-bold text-gray-900 dark:text-white tracking-tight">
              {getCheckName(violation.check_id)}
            </h2>
            {violation.domain && (
              <p className="text-xs text-gray-500 dark:text-gray-400 mt-1 capitalize">
                {violation.domain.replace(/_/g, " ")}
              </p>
            )}
          </div>

          {/* Details grid */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
            {/* Issue details — 2/3 */}
            <div className="lg:col-span-2 bg-white dark:bg-[#111] border border-gray-100 dark:border-white/5 rounded-2xl px-6 py-5 shadow-sm space-y-4">
              <h3 className="text-[10px] font-semibold uppercase tracking-widest text-gray-500 dark:text-gray-400">
                Issue Details
              </h3>

              <div>
                <p className="text-xs text-gray-400 dark:text-gray-500 mb-0.5">
                  Resource
                </p>
                <p className="text-sm font-mono text-gray-900 dark:text-white break-all">
                  {violation.resource || "N/A"}
                </p>
              </div>

              <div>
                <p className="text-xs text-gray-400 dark:text-gray-500 mb-0.5">
                  Reason
                </p>
                <p className="text-sm text-gray-700 dark:text-gray-300 leading-relaxed">
                  {violation.reason || "No reason provided"}
                </p>
              </div>

              {(violation.first_detected || violation.last_evaluated) && (
                <div className="flex gap-8 pt-3 border-t border-gray-100 dark:border-white/5">
                  {violation.first_detected && (
                    <div>
                      <p className="text-xs text-gray-400 dark:text-gray-500 mb-0.5">
                        First Detected
                      </p>
                      <p className="text-xs text-gray-700 dark:text-gray-300">
                        {new Date(violation.first_detected).toLocaleString()}
                      </p>
                    </div>
                  )}
                  {violation.last_evaluated && (
                    <div>
                      <p className="text-xs text-gray-400 dark:text-gray-500 mb-0.5">
                        Last Evaluated
                      </p>
                      <p className="text-xs text-gray-700 dark:text-gray-300">
                        {new Date(violation.last_evaluated).toLocaleString()}
                      </p>
                    </div>
                  )}
                </div>
              )}
            </div>

            {/* Sidebar: risk score + compliance */}
            <div className="space-y-4">
              {violation.risk_score !== undefined && (
                <RiskScoreMeter score={violation.risk_score} />
              )}

              {hasCompliance && comp && (
                <div className="bg-white dark:bg-[#111] border border-gray-100 dark:border-white/5 rounded-2xl px-5 py-4 shadow-sm space-y-3">
                  <h3 className="text-[10px] font-semibold uppercase tracking-widest text-gray-500 dark:text-gray-400">
                    Compliance
                  </h3>
                  <ComplianceSection
                    label="CIS AWS"
                    controls={comp.cis_aws ?? []}
                  />
                  <ComplianceSection
                    label="NIST 800-53"
                    controls={comp.nist_800_53 ?? []}
                  />
                  <ComplianceSection
                    label="PCI DSS"
                    controls={comp.pci_dss ?? []}
                  />
                  <ComplianceSection
                    label="HIPAA"
                    controls={comp.hipaa ?? []}
                  />
                  <ComplianceSection
                    label="SOC 2"
                    controls={comp.soc2 ?? []}
                  />
                </div>
              )}
            </div>
          </div>

          {/* Remediation */}
          <div>
            <h3 className="text-sm font-semibold text-gray-900 dark:text-white mb-3">
              How to Fix
            </h3>
            <RemediationTabs
              checkId={violation.check_id}
              resource={violation.resource ?? ""}
            />
          </div>
        </>
      )}
    </div>
  );
}
