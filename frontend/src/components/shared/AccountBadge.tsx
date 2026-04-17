import { useAccount } from "@/hooks/useAccount";

export default function AccountBadge() {
  const { selectedAccount, accounts } = useAccount();
  const account = accounts.find(
    (a) => a.account_id === selectedAccount,
  );
  const label = account
    ? `Viewing: ${account.account_name}`
    : "All Accounts";

  return (
    <span
      className={[
        "inline-flex items-center px-2 py-0.5 rounded-md",
        "text-xs font-medium",
        account
          ? "bg-blue-50 dark:bg-blue-500/10"
            + " text-blue-700 dark:text-blue-400"
            + " border border-blue-200 dark:border-blue-500/20"
          : "bg-gray-100 dark:bg-white/5"
            + " text-gray-500 dark:text-gray-400"
            + " border border-gray-200 dark:border-white/10",
      ].join(" ")}
    >
      {label}
    </span>
  );
}
