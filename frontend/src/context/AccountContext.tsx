import {
  useCallback,
  useEffect,
  useMemo,
  useState,
} from "react";
import type { ReactNode } from "react";
import { getAccounts } from "@/api/accounts";
import type { TargetAccount } from "@/types/account";
import { AccountContext } from "./accountContextValue";

export function AccountProvider({
  children,
}: {
  children: ReactNode;
}) {
  const [selectedAccount, setSelectedAccountState] =
    useState<string>("");
  const [accounts, setAccounts] = useState<
    TargetAccount[]
  >([]);
  const [isLoading, setIsLoading] = useState(true);
  const [refreshKey, setRefreshKey] = useState(0);

  useEffect(() => {
    let cancelled = false;
    setIsLoading(true);
    getAccounts()
      .then((data) => {
        if (!cancelled) {
          setAccounts(data);
          setIsLoading(false);
        }
      })
      .catch(() => {
        if (!cancelled) {
          setIsLoading(false);
        }
      });
    return () => {
      cancelled = true;
    };
  }, [refreshKey]);

  const setSelectedAccount = useCallback(
    (accountId: string) => {
      setSelectedAccountState(accountId);
    },
    [],
  );

  const refresh = useCallback(() => {
    setRefreshKey((k) => k + 1);
  }, []);

  const value = useMemo(
    () => ({
      selectedAccount,
      accounts,
      isLoading,
      setSelectedAccount,
      refresh,
    }),
    [
      selectedAccount,
      accounts,
      isLoading,
      setSelectedAccount,
      refresh,
    ],
  );

  return (
    <AccountContext.Provider value={value}>
      {children}
    </AccountContext.Provider>
  );
}
