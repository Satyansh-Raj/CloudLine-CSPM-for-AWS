import { useAccount } from "@/hooks/useAccount";
import CustomSelect from "@/components/shared/CustomSelect";

function BuildingIcon() {
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
        d="M19 21V5a2 2 0 00-2-2H7a2 2 0 00-2
         2v16m14 0H5m14 0h2m-16 0H3m2-9h.01M12
         8h.01M12 12h.01M12 16h.01M8 12h.01M8
         16h.01"
      />
    </svg>
  );
}

export default function AccountSelector() {
  const { selectedAccount, accounts, setSelectedAccount } = useAccount();

  const options = [
    { value: "", label: "Root Account" },
    ...accounts.map((a) => ({
      value: a.account_id,
      label: `${a.account_name} (${a.account_id})`,
    })),
  ];

  return (
    <div className="flex items-center gap-1.5 text-gray-400 dark:text-gray-600 -ml-[3px]">
      <BuildingIcon />
      <CustomSelect
        value={selectedAccount}
        onChange={setSelectedAccount}
        options={options}
        aria-label="Select account"
      />
    </div>
  );
}
