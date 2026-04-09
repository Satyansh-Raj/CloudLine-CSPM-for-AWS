interface Props {
  severity: string;
}

const styles: Record<string, string> = {
  High:
    "bg-red-100 text-red-800"
    + " dark:bg-red-900/30 dark:text-red-400",
  Medium:
    "bg-yellow-100 text-yellow-800"
    + " dark:bg-yellow-900/30 dark:text-yellow-400",
  Low:
    "bg-green-100 text-green-800"
    + " dark:bg-green-900/30 dark:text-green-400",
};

export default function DataSensitivityBadge({
  severity,
}: Props) {
  const cls =
    styles[severity]
    ?? "bg-gray-100 text-gray-800"
       + " dark:bg-gray-700 dark:text-gray-300";

  return (
    <span
      className={
        "inline-flex items-center px-2 py-0.5"
        + " rounded text-xs font-medium " + cls
      }
    >
      {severity}
    </span>
  );
}
