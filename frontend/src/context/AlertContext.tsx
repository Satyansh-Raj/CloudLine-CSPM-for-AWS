import { useCallback, useMemo, useReducer } from "react";
import type { ReactNode } from "react";
import type { WsAlert, WsMessage, WsStatus } from "@/types";
import { AlertContext } from "./alertContextValue";

const MAX_ALERTS = 50;

interface AlertState {
  alerts: WsAlert[];
  toasts: WsAlert[];
  status: WsStatus;
}

type AlertAction =
  | { type: "ADD_ALERT"; alert: WsAlert }
  | { type: "DISMISS_TOAST"; id: string }
  | { type: "MARK_READ"; id: string }
  | { type: "MARK_ALL_READ" }
  | { type: "CLEAR_ALERTS" }
  | { type: "SET_STATUS"; status: WsStatus };

function alertReducer(
  state: AlertState,
  action: AlertAction,
): AlertState {
  switch (action.type) {
    case "ADD_ALERT":
      return {
        ...state,
        alerts: [
          action.alert,
          ...state.alerts,
        ].slice(0, MAX_ALERTS),
        toasts: [
          action.alert,
          ...state.toasts,
        ].slice(0, 5),
      };
    case "DISMISS_TOAST":
      return {
        ...state,
        toasts: state.toasts.filter(
          (t) => t.id !== action.id,
        ),
      };
    case "MARK_READ":
      return {
        ...state,
        alerts: state.alerts.map((a) =>
          a.id === action.id
            ? { ...a, read: true }
            : a,
        ),
      };
    case "MARK_ALL_READ":
      return {
        ...state,
        alerts: state.alerts.map((a) => ({
          ...a,
          read: true,
        })),
      };
    case "CLEAR_ALERTS":
      return { ...state, alerts: [], toasts: [] };
    case "SET_STATUS":
      return { ...state, status: action.status };
    default:
      return state;
  }
}

let nextId = 0;

export function AlertProvider({
  children,
}: {
  children: ReactNode;
}) {
  const [state, dispatch] = useReducer(alertReducer, {
    alerts: [],
    toasts: [],
    status: "disconnected",
  });

  const addAlert = useCallback((msg: WsMessage) => {
    if (!msg.data) return;
    const alert: WsAlert = {
      id: `ws-${++nextId}-${Date.now()}`,
      type: msg.type,
      data: msg.data,
      receivedAt: Date.now(),
      read: false,
    };
    dispatch({ type: "ADD_ALERT", alert });
  }, []);

  const dismissToast = useCallback((id: string) => {
    dispatch({ type: "DISMISS_TOAST", id });
  }, []);

  const markRead = useCallback((id: string) => {
    dispatch({ type: "MARK_READ", id });
  }, []);

  const markAllRead = useCallback(() => {
    dispatch({ type: "MARK_ALL_READ" });
  }, []);

  const clearAlerts = useCallback(() => {
    dispatch({ type: "CLEAR_ALERTS" });
  }, []);

  const setStatus = useCallback(
    (status: WsStatus) => {
      dispatch({ type: "SET_STATUS", status });
    },
    [],
  );

  const unreadCount = useMemo(
    () => state.alerts.filter((a) => !a.read).length,
    [state.alerts],
  );

  const value = useMemo(
    () => ({
      alerts: state.alerts,
      toasts: state.toasts,
      status: state.status,
      unreadCount,
      addAlert,
      dismissToast,
      markRead,
      markAllRead,
      clearAlerts,
      setStatus,
    }),
    [
      state.alerts,
      state.toasts,
      state.status,
      unreadCount,
      addAlert,
      dismissToast,
      markRead,
      markAllRead,
      clearAlerts,
      setStatus,
    ],
  );

  return (
    <AlertContext.Provider value={value}>
      {children}
    </AlertContext.Provider>
  );
}
