import type { Exposure } from "@/types/inventory";

interface Props {
  exposure: Exposure | string;
}

const styles: Record<string, string> = {
  internet:
    "bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400",
  private:
    "bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400",
  unknown:
    "bg-ghost-cream text-slate-gray dark:bg-white/5 dark:text-slate-gray",
};

const labels: Record<string, string> = {
  internet: "EXPOSED",
  private: "INTERNAL",
  unknown: "UNKNOWN",
};

export default function ExposureBadge({ exposure }: Props) {
  const cls = styles[exposure] ?? styles.unknown;

  return (
    <span
      className={`inline-flex items-center px-2 py-0.5 rounded-pill text-xs font-bold tracking-wide ${cls}`}
    >
      {labels[exposure] ?? "UNKNOWN"}
    </span>
  );
}
