import { createContext } from "react";

export interface RegionContextValue {
  selectedRegion: string;
  regions: string[];
  isLoading: boolean;
  setSelectedRegion: (region: string) => void;
}

export const RegionContext =
  createContext<RegionContextValue>(
    null as unknown as RegionContextValue,
  );
