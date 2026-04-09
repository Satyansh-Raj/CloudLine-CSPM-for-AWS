import { useMacieFindings } from "@/hooks";
import DataSensitivityBadge from "@/components/shared/DataSensitivityBadge";
import type { MacieFindingsParams } from "@/types/macie";

interface Props {
  bucketName?: string;
  accountId?: string;
}

function formatDate(iso: string): string {
  return new Date(iso).toLocaleDateString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
  });
}

function shortType(type: string): string {
  // "SensitiveData:S3Object/Personal" → "Personal"
  const slash = type.lastIndexOf("/");
  return slash >= 0 ? type.slice(slash + 1) : type;
}

export default function MacieFindingsPanel({
  bucketName,
  accountId,
}: Props) {
  const params: MacieFindingsParams = {};
  if (bucketName) params.bucket_name = bucketName;
  if (accountId) params.account_id = accountId;

  const { data, isLoading } = useMacieFindings(
    Object.keys(params).length ? params : undefined,
  );

  return (
    <div className="bg-white dark:bg-[#111] border border-gray-100 dark:border-white/5 rounded-2xl p-5 shadow-sm">
      <h2 className="text-xs uppercase tracking-widest text-gray-400 dark:text-gray-500 mb-4">
        Macie Findings
      </h2>

      {isLoading && (
        <div className="space-y-3 animate-pulse">
          {Array.from({ length: 3 }).map((_, i) => (
            <div
              key={i}
              className="h-10 bg-gray-100 dark:bg-white/5 rounded-xl"
            />
          ))}
        </div>
      )}

      {!isLoading && (!data || data.length === 0) && (
        <p className="text-sm text-gray-400 dark:text-gray-500 text-center py-4">
          No Macie findings for this resource.
        </p>
      )}

      {!isLoading && data && data.length > 0 && (
        <ul className="space-y-2">
          {data.map((f) => (
            <li
              key={f.finding_id}
              className="flex flex-wrap items-center gap-2 p-3 rounded-xl bg-gray-50 dark:bg-white/[0.03] border border-gray-100 dark:border-white/5"
            >
              <DataSensitivityBadge severity={f.severity} />
              <span className="text-xs font-medium text-gray-700 dark:text-gray-300">
                {f.bucket_name}
              </span>
              <span className="text-xs text-gray-400 dark:text-gray-500">
                {shortType(f.type)} — {f.count} object
                {f.count !== 1 ? "s" : ""}
              </span>
              <span className="ml-auto text-xs text-gray-400 dark:text-gray-500">
                {formatDate(f.first_observed_at)}
              </span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
