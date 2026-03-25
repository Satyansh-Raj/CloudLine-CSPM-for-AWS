import { createContext } from "react";
import type { AccountContextValue } from "@/types/account";

export const AccountContext =
  createContext<AccountContextValue>(
    null as unknown as AccountContextValue,
  );
