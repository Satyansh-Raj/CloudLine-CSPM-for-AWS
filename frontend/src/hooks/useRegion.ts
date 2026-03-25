import { useContext } from "react";
import {
  RegionContext,
  type RegionContextValue,
} from "@/context/regionContextValue";

export function useRegion(): RegionContextValue {
  const ctx = useContext(RegionContext);
  if (!ctx) {
    throw new Error(
      "useRegion must be used within RegionProvider",
    );
  }
  return ctx;
}
