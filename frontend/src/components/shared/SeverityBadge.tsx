import type { Severity } from "@/types";

interface Props {
  severity: Severity | string;
}

const styles: Record<string, string> = {
  critical: "bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400",
  high: "bg-orange-100 text-orange-800 dark:bg-orange-900/30 dark:text-orange-400",
  medium:
    "bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-400",
  low: "bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400",
};

export default function SeverityBadge({ severity }: Props) {
  const cls =
    styles[severity] ??
    "bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-300";

  return (
    <span
      className={`inline-flex items-center px-2.5 py-0.5 rounded-pill text-xs font-medium capitalize ${cls}`}
    >
      {severity}
    </span>
  );
}
