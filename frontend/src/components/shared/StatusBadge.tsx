import type { ViolationStatus } from "@/types";

interface Props {
  status: ViolationStatus | string;
}

const styles: Record<string, string> = {
  alarm:
    "bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400",
  ok:
    "bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400",
  error:
    "bg-orange-100 text-orange-800 dark:bg-orange-900/30 dark:text-orange-400",
  skip:
    "bg-gray-100 text-gray-600 dark:bg-gray-700 dark:text-gray-400",
};

export default function StatusBadge({ status }: Props) {
  const cls =
    styles[status] ??
    "bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-300";

  return (
    <span
      className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium uppercase ${cls}`}
    >
      {status}
    </span>
  );
}
