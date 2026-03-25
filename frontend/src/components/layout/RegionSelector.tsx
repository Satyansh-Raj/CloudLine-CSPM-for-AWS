import { useRegion } from "@/hooks/useRegion";

function GlobeIcon() {
  return (
    <svg
      className="w-4 h-4 shrink-0"
      fill="none"
      stroke="currentColor"
      viewBox="0 0 24 24"
      aria-hidden="true"
    >
      <path
        strokeLinecap="round"
        strokeLinejoin="round"
        strokeWidth="1.8"
        d="M12 21a9 9 0 100-18 9 9 0 000 18z
           M3.6 9h16.8M3.6 15h16.8
           M12 3c-2.4 2.4-3.8 5.6-3.8 9s1.4
           6.6 3.8 9M12 3c2.4 2.4 3.8 5.6
           3.8 9s-1.4 6.6-3.8 9"
      />
    </svg>
  );
}

export default function RegionSelector() {
  const { selectedRegion, regions, setSelectedRegion } =
    useRegion();

  return (
    <div className="flex items-center gap-1.5 text-gray-400 dark:text-gray-600">
      <GlobeIcon />
      <select
        value={selectedRegion}
        onChange={(e) =>
          setSelectedRegion(e.target.value)
        }
        className="text-xs bg-transparent border-none outline-none cursor-pointer text-gray-500 dark:text-gray-500 hover:text-gray-700 dark:hover:text-gray-300 transition-colors"
        aria-label="Select region"
      >
        <option value="">All Regions</option>
        {regions.map((r) => (
          <option key={r} value={r}>
            {r}
          </option>
        ))}
      </select>
    </div>
  );
}
