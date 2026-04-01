import { useNavigate, useParams, useLocation } from "react-router-dom";
import {
  useViolations,
  useCreateJiraTicket,
  useDeleteJiraTicket,
} from "@/hooks";
import {
  SeverityBadge,
  StatusBadge,
  RiskScoreMeter,
  ComplianceSection,
} from "@/components/shared";
import { getCheckName } from "@/constants/checkNames";
import { getComplianceMapping } from "@/constants/complianceMappings";
import RemediationTabs from "@/components/violations/RemediationTabs";
import { fromViolationResource } from "@/utils/violationUrl";
import { useAccount } from "@/hooks/useAccount";
import { useRegion } from "@/hooks/useRegion";
import type { Violation } from "@/types";
import type { ApiError } from "@/api/client";

function JiraSection({
  violation,
  accountId,
  region,
}: {
  violation: Violation;
  accountId: string;
  region: string;
}) {
  const { mutate, isPending, isError, error } = useCreateJiraTicket();
  const {
    mutate: unlinkTicket,
    isPending: isDeleting,
    isError: isDeleteError,
    error: deleteError,
  } = useDeleteJiraTicket();

  const errorMessage =
    isError && error
      ? ((error as unknown as ApiError).message ?? error.message)
      : null;

  const deleteErrorMessage =
    isDeleteError && deleteError
      ? ((deleteError as unknown as ApiError).message ?? deleteError.message)
      : null;

  // Ticket already exists — show badge link + delete button
  if (violation.ticket_id) {
    const ticketBadge = violation.ticket_url ? (
      <a
        href={violation.ticket_url}
        target="_blank"
        rel="noopener noreferrer"
        data-testid="ticket-link"
        className="bg-blue-100 dark:bg-blue-500/20 text-blue-600 dark:text-blue-400 rounded-full px-3 py-1 text-xs font-medium hover:opacity-80 transition-opacity"
      >
        {violation.ticket_id}
      </a>
    ) : (
      <span className="bg-blue-100 dark:bg-blue-500/20 text-blue-600 dark:text-blue-400 rounded-full px-3 py-1 text-xs font-medium">
        {violation.ticket_id}
      </span>
    );

    return (
      <div className="mt-2 space-y-2">
        {deleteErrorMessage && (
          <div
            data-testid="delete-ticket-error"
            className="rounded-lg bg-red-50 dark:bg-red-500/10 border border-red-100 dark:border-red-500/20 px-4 py-2 text-xs text-red-600 dark:text-red-400"
          >
            {deleteErrorMessage}
          </div>
        )}
        <div className="flex items-center gap-2">
          {ticketBadge}
          <button
            data-testid="delete-ticket-btn"
            disabled={isDeleting}
            onClick={() =>
              unlinkTicket({
                account_id: accountId,
                region,
                check_id: violation.check_id,
                resource_id: violation.resource ?? "",
              })
            }
            className="flex items-center gap-1 text-xs text-red-500 hover:text-red-700 dark:text-red-400 dark:hover:text-red-300 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
            title="Unlink Jira ticket"
          >
            {isDeleting ? (
              <span className="w-3 h-3 rounded-full border-2 border-red-300 border-t-red-500 animate-spin" />
            ) : (
              <svg
                className="w-3.5 h-3.5"
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M6 18L18 6M6 6l12 12"
                />
              </svg>
            )}
            {isDeleting ? "Removing..." : "Remove"}
          </button>
        </div>
      </div>
    );
  }

  // No ticket yet — show create button
  return (
    <div className="mt-2 space-y-2">
      {errorMessage && (
        <div
          data-testid="ticket-error"
          className="rounded-lg bg-red-50 dark:bg-red-500/10 border border-red-100 dark:border-red-500/20 px-4 py-2 text-xs text-red-600 dark:text-red-400"
        >
          {errorMessage}
        </div>
      )}
      <button
        data-testid="create-ticket-btn"
        disabled={isPending}
        onClick={() =>
          mutate({
            account_id: accountId,
            region,
            check_id: violation.check_id,
            resource_id: violation.resource ?? "",
          })
        }
        className="flex items-center gap-2 bg-blue-500 hover:bg-blue-600 disabled:opacity-50 disabled:cursor-not-allowed text-white rounded-lg px-4 py-2 text-sm font-medium transition-colors"
      >
        {isPending ? (
          <>
            <span
              data-testid="ticket-loading"
              className="w-3.5 h-3.5 rounded-full border-2 border-white/30 border-t-white animate-spin"
            />
            Creating...
          </>
        ) : (
          <>
            {/* Jira-style ticket icon */}
            <svg
              className="w-3.5 h-3.5"
              viewBox="0 0 24 24"
              fill="currentColor"
              aria-hidden="true"
            >
              <path d="M11.571 11.513H0a5.218 5.218 0 0 0 5.232 5.215h2.13v2.057A5.215 5.215 0 0 0 12.575 24V12.518a1.005 1.005 0 0 0-1.005-1.005zm5.723-5.756H5.757a5.215 5.215 0 0 0 5.215 5.214h2.129v2.058a5.218 5.218 0 0 0 5.215 5.214V6.762a1.005 1.005 0 0 0-1.022-1.005zM23.017 0H11.459a5.215 5.215 0 0 0 5.215 5.215h2.129v2.057A5.215 5.215 0 0 0 24.019 12.49V1.005A1.001 1.001 0 0 0 23.017 0z" />
            </svg>
            Create Jira Ticket
          </>
        )}
      </button>
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
  const freshViolation = data?.find(
    (v) => v.check_id === checkId && v.resource === resource,
  );
  const violation: Violation | undefined = freshViolation ?? stateViolation;

  const { selectedAccount } = useAccount();
  const { selectedRegion } = useRegion();

  const accountId = violation?.account_id ?? selectedAccount ?? "";
  const region = violation?.region ?? selectedRegion ?? "";

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
            <JiraSection
              violation={violation}
              accountId={accountId}
              region={region}
            />
          </div>

          {/* Details grid */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
            {/* Issue details — 2/3 */}
            <div className="lg:col-span-2 bg-white dark:bg-[#111] border border-gray-100 dark:border-white/5 rounded-2xl px-6 py-5 shadow-sm flex flex-col">
              <div className="space-y-4">
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
              </div>

              {(violation.first_detected || violation.last_evaluated) && (
                <div className="flex gap-8 pt-3 mt-auto border-t border-gray-100 dark:border-white/5">
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
