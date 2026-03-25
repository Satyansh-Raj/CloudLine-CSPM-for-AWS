import { useContext } from "react";
import {
  AccountContext,
} from "@/context/accountContextValue";
import type { AccountContextValue } from "@/types/account";

export function useAccount(): AccountContextValue {
  const ctx = useContext(AccountContext);
  if (!ctx) {
    throw new Error(
      "useAccount must be used within"
      + " AccountProvider",
    );
  }
  return ctx;
}
