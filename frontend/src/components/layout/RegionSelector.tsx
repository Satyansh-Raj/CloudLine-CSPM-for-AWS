import { CustomSelect } from "@/components/shared";
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
  const { selectedRegion, regions, setSelectedRegion } = useRegion();

  return (
    <div className="flex items-center gap-1.5">
      <GlobeIcon />
      <CustomSelect
        value={selectedRegion}
        onChange={setSelectedRegion}
        aria-label="Select region"
        options={[
          { value: "", label: "All Regions" },
          ...regions.map((r) => ({ value: r, label: r })),
        ]}
      />
    </div>
  );
}
