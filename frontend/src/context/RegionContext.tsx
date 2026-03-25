import {
  useCallback,
  useEffect,
  useMemo,
  useState,
} from "react";
import type { ReactNode } from "react";
import { getRegions } from "@/api/regions";
import { RegionContext } from "./regionContextValue";

export function RegionProvider({
  children,
}: {
  children: ReactNode;
}) {
  const [selectedRegion, setSelectedRegionState] =
    useState<string>("");
  const [regions, setRegions] = useState<string[]>(
    [],
  );
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    setIsLoading(true);
    getRegions()
      .then((resp) => {
        if (!cancelled) {
          setRegions(resp.regions);
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
