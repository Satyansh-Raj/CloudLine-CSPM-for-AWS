import {
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
} from "react";
import type { ReactNode } from "react";
import { getRegions } from "@/api/regions";
import { AccountContext } from "./accountContextValue";
import { RegionContext } from "./regionContextValue";

export function RegionProvider({
  children,
}: {
  children: ReactNode;
}) {
  const { selectedAccount, accounts } =
    useContext(AccountContext);

  const [selectedRegion, setSelectedRegionState] =
    useState<string>("");
  const [masterRegions, setMasterRegions] = useState<
    string[]
  >([]);
  const [isLoading, setIsLoading] = useState(true);

  // Fetch master account regions once
  useEffect(() => {
    let cancelled = false;
    setIsLoading(true);
    getRegions()
      .then((resp) => {
        if (!cancelled) {
          setMasterRegions(resp.regions);
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
  }, []);

  // Derive active regions from selected account or master
  const regions = useMemo(() => {
    if (!selectedAccount) return masterRegions;
    const acct = accounts.find(
      (a) => a.account_id === selectedAccount,
    );
    return acct?.regions?.length
      ? acct.regions
      : masterRegions;
  }, [selectedAccount, accounts, masterRegions]);

  // Reset region when account changes if current region
  // not available in new account's region list
  useEffect(() => {
    if (
      selectedRegion &&
      regions.length > 0 &&
      !regions.includes(selectedRegion)
    ) {
      setSelectedRegionState("");
    }
  }, [regions, selectedRegion]);

  const setSelectedRegion = useCallback(
    (region: string) => {
      setSelectedRegionState(region);
    },
    [],
  );

  const value = useMemo(
    () => ({
      selectedRegion,
      regions,
      isLoading,
      setSelectedRegion,
    }),
    [selectedRegion, regions, isLoading, setSelectedRegion],
  );

  return (
    <RegionContext.Provider value={value}>
      {children}
    </RegionContext.Provider>
  );
}
