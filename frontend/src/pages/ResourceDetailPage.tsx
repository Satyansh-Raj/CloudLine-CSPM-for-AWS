import { Link, useLocation } from "react-router-dom";
import { useViolations } from "@/hooks";
import { MacieFindingsPanel } from "@/components/macie";
import { EyebrowLabel } from "@/components/shared";
import type { Resource } from "@/types/inventory";
import type { Violation } from "@/types";

const SEVERITY_COLORS: Record<string, string> = {
  critical: "bg-red-100 text-red-700 dark:bg-red-500/10 dark:text-red-400",
  high: "bg-orange-100 text-orange-700 dark:bg-orange-500/10 dark:text-orange-400",
  medium:
    "bg-yellow-100 text-yellow-700 dark:bg-yellow-500/10 dark:text-yellow-400",
  low: "bg-blue-100 text-blue-700 dark:bg-blue-500/10 dark:text-blue-400",
};

const EXPOSURE_COLORS: Record<string, string> = {
  internet: "text-red-600 dark:text-red-400",
  private: "text-green-600 dark:text-green-400",
  unknown: "text-slate-gray",
};

function MetaRow({
  label,
  value,
  valueClass,
}: {
  label: string;
  value: string;
  valueClass?: string;
}) {
  return (
    <div className="flex items-start justify-between gap-4 py-2.5 border-b border-ghost-cream dark:border-white/5 last:border-0">
      <span className="text-xs uppercase tracking-widest text-slate-gray/70 shrink-0 pt-0.5">
        {label}
      </span>
      <span
        className={
          valueClass ??
          "text-sm font-medium text-ink-black dark:text-canvas-cream text-right break-all"
        }
      >
        {value}
      </span>
    </div>
  );
}

function RiskBadge({ score }: { score: number }) {
  let color =
    "text-green-600 dark:text-green-400 bg-green-50 dark:bg-green-500/10";
  if (score >= 70)
    color = "text-red-600 dark:text-red-400 bg-red-50 dark:bg-red-500/10";
  else if (score >= 40)
    color =
      "text-orange-600 dark:text-orange-400 bg-orange-50 dark:bg-orange-500/10";

  return (
    <div
      className={`inline-flex items-center gap-1.5 px-3 py-1 rounded-pill text-2xl font-bold ${color}`}
    >
      {score}
      <span className="text-xs font-normal opacity-70">/ 100</span>
    </div>
  );
}

export default function ResourceDetailPage() {
  const location = useLocation();
  const resource = location.state?.resource as Resource | undefined;

  const { data: allViolations, isLoading: violationsLoading } = useViolations({
    status: "alarm",
  });

  if (!resource) {
    return (
      <div className="flex items-center justify-center min-h-[40vh]">
        <div className="bg-lifted-cream dark:bg-ink-black border border-ghost-cream dark:border-white/5 rounded-hero p-10 shadow-elev-1 text-center">
          <p className="text-lg font-semibold text-ink-black dark:text-canvas-cream">
            Resource not found
          </p>
          <p className="text-sm text-slate-gray mt-1">
            No resource data was passed to this page.
          </p>
          <Link
            to="/inventory"
            aria-label="back to inventory"
            className="mt-4 inline-block text-sm text-link-blue hover:underline"
          >
            Back to Inventory
          </Link>
        </div>
      </div>
    );
  }

  const violations: Violation[] = allViolations
    ? allViolations.filter((v) => v.resource === resource.resource_id)
    : [];

  const liveTotal = violations.length;
  const liveCritical = violations.filter(
    (v) => v.severity === "critical",
  ).length;
  const liveHigh = violations.filter((v) => v.severity === "high").length;

  const daysRunning = resource.created_at
    ? Math.max(
        1,
        Math.ceil(
          (Date.now() - new Date(resource.created_at).getTime()) / 86400000,
        ),
      )
    : null;

  const daysRunningLabel =
    daysRunning === null
      ? "N/A"
      : daysRunning === 1
        ? "1 day"
        : `${daysRunning} days`;

  const lastSeenFormatted = new Date(resource.last_seen).toLocaleString(
    undefined,
    {
      year: "numeric",
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    },
  );

  const tagEntries = Object.entries(resource.tags ?? {});

  return (
    <div className="space-y-5">
      {/* Back link */}
      <Link
        to={`/inventory/${resource.technology_category}`}
        aria-label={`back to ${resource.technology_category}`}
        className="inline-flex items-center gap-1.5 text-sm text-slate-gray hover:text-ink-black dark:hover:text-canvas-cream transition-colors"
      >
        <svg
          xmlns="http://www.w3.org/2000/svg"
          className="w-4 h-4"
          viewBox="0 0 20 20"
          fill="currentColor"
          aria-hidden="true"
        >
          <path
            fillRule="evenodd"
            d="M9.707 16.707a1 1 0 01-1.414 0l-6-6a1 1 0 010-1.414l6-6a1 1 0 011.414 1.414L5.414 9H17a1 1 0 110 2H5.414l4.293 4.293a1 1 0 010 1.414z"
            clipRule="evenodd"
          />
        </svg>
        Back
      </Link>

      {/* Heading */}
      <div>
        <EyebrowLabel>Resource Detail</EyebrowLabel>
        <h1 className="text-2xl font-bold text-ink-black dark:text-canvas-cream tracking-tight break-all mt-0.5">
          {resource.resource_name}
        </h1>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        {/* Left column: metadata + tags */}
        <div className="lg:col-span-2 space-y-5">
          {/* Metadata card */}
          <div className="bg-lifted-cream dark:bg-ink-black border border-ghost-cream dark:border-white/5 rounded-hero p-5 shadow-elev-1">
            <h2 className="text-xs uppercase tracking-widest text-slate-gray mb-3">
              Metadata
            </h2>
            <MetaRow label="Resource Type" value={resource.resource_type} />
            <MetaRow label="Service" value={resource.service} />
            <MetaRow label="Region" value={resource.region} />
            <MetaRow label="Account" value={resource.account_id} />
            <MetaRow
              label="Exposure"
              value={resource.exposure}
              valueClass={`text-sm font-semibold text-right ${EXPOSURE_COLORS[resource.exposure] ?? ""}`}
            />
            <MetaRow label="Environment" value={resource.environment} />
            <MetaRow label="Days Running" value={daysRunningLabel} />
            <MetaRow label="Last Seen" value={lastSeenFormatted} />
          </div>

          {/* Tags card */}
          {tagEntries.length > 0 && (
            <div className="bg-lifted-cream dark:bg-ink-black border border-ghost-cream dark:border-white/5 rounded-hero p-5 shadow-elev-1">
              <h2 className="text-xs uppercase tracking-widest text-slate-gray mb-3">
                Tags
              </h2>
              <div className="flex flex-wrap gap-2">
                {tagEntries.map(([key, val]) => (
                  <span
                    key={key}
                    className="inline-flex items-center gap-1 px-2.5 py-1 rounded-pill bg-ghost-cream dark:bg-white/5 text-xs text-ink-black dark:text-canvas-cream"
                  >
                    <span className="font-medium">{key}</span>
                    <span className="text-slate-gray/50">=</span>
                    <span>{val}</span>
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Right column: risk score + violation summary */}
        <div className="space-y-5">
          {/* Risk score card */}
          <div className="bg-lifted-cream dark:bg-ink-black border border-ghost-cream dark:border-white/5 rounded-hero p-5 shadow-elev-1 text-center">
            <p className="text-xs uppercase tracking-widest text-slate-gray mb-3">
              Risk Score
            </p>
            <RiskBadge score={resource.risk_score} />
          </div>

          {/* Violation summary card */}
          <div className="bg-lifted-cream dark:bg-ink-black border border-ghost-cream dark:border-white/5 rounded-hero p-5 shadow-elev-1">
            <h2 className="text-xs uppercase tracking-widest text-slate-gray mb-3">
              Violation Summary
            </h2>
            {!violationsLoading && liveTotal === 0 ? (
              <p className="text-sm font-semibold text-green-600 dark:text-green-400 text-center py-2">
                All Clear
              </p>
            ) : (
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-xs text-slate-gray">Total</span>
                  <span className="text-sm font-bold text-ink-black dark:text-canvas-cream">
                    {liveTotal}
                  </span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-xs text-slate-gray">Critical</span>
                  <span className="text-sm font-bold text-red-600 dark:text-red-400">
                    {liveCritical}
                  </span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-xs text-slate-gray">High</span>
                  <span className="text-sm font-bold text-orange-600 dark:text-orange-400">
                    {liveHigh}
                  </span>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Macie findings — S3 only */}
      {resource.service === "s3" && (
        <MacieFindingsPanel
          bucketName={resource.resource_name}
          accountId={resource.account_id}
        />
      )}

      {/* Violations list */}
      <div className="bg-lifted-cream dark:bg-ink-black border border-ghost-cream dark:border-white/5 rounded-hero p-5 shadow-elev-1">
        <h2 className="text-xs uppercase tracking-widest text-slate-gray mb-4">
          Active Violations
        </h2>

        {violationsLoading && (
          <div className="space-y-3 animate-pulse">
            {Array.from({ length: 3 }).map((_, i) => (
              <div
                key={i}
                className="h-14 bg-ghost-cream dark:bg-white/5 rounded-xl"
              />
            ))}
          </div>
        )}

        {!violationsLoading && violations.length === 0 && (
          <p className="text-sm text-slate-gray text-center py-4">
            No active violations for this resource.
          </p>
        )}

        {!violationsLoading && violations.length > 0 && (
          <ul className="space-y-3">
            {violations.map((v) => (
              <li
                key={v.check_id}
                className="flex flex-col sm:flex-row sm:items-start gap-2 p-3 rounded-hero bg-canvas-cream dark:bg-white/[0.03] border border-ghost-cream dark:border-white/5"
              >
                <div className="flex items-center gap-2 shrink-0">
                  <span
                    className={`inline-block px-2 py-0.5 rounded-pill text-[10px] uppercase font-semibold tracking-wider ${SEVERITY_COLORS[v.severity] ?? ""}`}
                  >
                    {v.severity}
                  </span>
                  <span className="text-xs font-mono font-medium text-ink-black dark:text-canvas-cream">
                    {v.check_id}
                  </span>
                </div>
                <p className="text-xs text-slate-gray sm:ml-auto">
                  {v.reason}
                </p>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}
