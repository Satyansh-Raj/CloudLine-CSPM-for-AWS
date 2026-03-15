import { createContext } from "react";
import type { WsAlert, WsMessage, WsStatus } from "@/types";

export interface AlertContextValue {
  alerts: WsAlert[];
  toasts: WsAlert[];
  status: WsStatus;
  unreadCount: number;
  addAlert: (msg: WsMessage) => void;
  dismissToast: (id: string) => void;
  markRead: (id: string) => void;
  markAllRead: () => void;
  clearAlerts: () => void;
  setStatus: (status: WsStatus) => void;
}

export const AlertContext =
  createContext<AlertContextValue>(
    null as unknown as AlertContextValue,
  );
