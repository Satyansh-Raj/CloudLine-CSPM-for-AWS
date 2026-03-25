export default function ComplianceSection({
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
