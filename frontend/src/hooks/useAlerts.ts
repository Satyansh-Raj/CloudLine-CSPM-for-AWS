import { useContext } from "react";
import {
  AlertContext,
  type AlertContextValue,
} from "@/context/alertContextValue";

export function useAlerts(): AlertContextValue {
  const ctx = useContext(AlertContext);
  if (!ctx) {
    throw new Error(
      "useAlerts must be used within AlertProvider",
    );
  }
  return ctx;
}
