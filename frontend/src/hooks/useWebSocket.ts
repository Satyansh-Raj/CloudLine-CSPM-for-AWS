import { useEffect, useRef } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { useAlerts } from "./useAlerts";
import { AUTH_KEY } from "@/context/AuthContext";
import type { WsMessage } from "@/types";

const PING_INTERVAL = 30_000;
const RECONNECT_BASE = 1_000;
const RECONNECT_MAX = 30_000;

function getWsUrl(): string {
  const wsUrl = import.meta.env.VITE_WS_URL || "/ws";
  const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
  const host = window.location.host;
  const base = wsUrl.startsWith("/")
    ? `${protocol}//${host}${wsUrl}/v1/events`
    : `${wsUrl}/v1/events`;

  // Append access token so the server can authenticate the WS upgrade.
  const stored = localStorage.getItem(AUTH_KEY);
  if (stored) {
    try {
      const { accessToken } = JSON.parse(stored) as {
        accessToken?: string;
      };
      if (accessToken) {
        return `${base}?token=${encodeURIComponent(accessToken)}`;
      }
    } catch {
      // ignore malformed storage
    }
  }
  return base;
}

const INVALIDATION_KEYS = [
  ["driftAlerts"],
  ["violations"],
  ["compliance"],
  ["riskSummary"],
  ["iam-graph"],
];

export function useWebSocket() {
  const wsRef = useRef<WebSocket | null>(null);
  const pingRef = useRef<ReturnType<typeof setInterval> | undefined>(undefined);
  const retryRef = useRef(0);
  const mountedRef = useRef(true);

  const queryClient = useQueryClient();
  const { addAlert, setStatus } = useAlerts();

  useEffect(() => {
    mountedRef.current = true;
    retryRef.current = 0;

    function handleMessage(msg: WsMessage) {
      if (msg.type === "pong") return;
      addAlert(msg);

      if (msg.type === "violation_new" || msg.type === "violation_resolved") {
        INVALIDATION_KEYS.forEach((key) =>
          queryClient.invalidateQueries({
            queryKey: key,
          }),
        );
      }
    }

    function connect() {
      if (!mountedRef.current) return;
      if (wsRef.current?.readyState === WebSocket.OPEN) {
        return;
      }

      const url = getWsUrl();

      setStatus("connecting");
      const ws = new WebSocket(url);
      wsRef.current = ws;

      ws.onopen = () => {
        if (!mountedRef.current) {
          ws.close();
          return;
        }
        retryRef.current = 0;
        setStatus("connected");

        pingRef.current = setInterval(() => {
          if (ws.readyState === WebSocket.OPEN) {
            ws.send("ping");
          }
        }, PING_INTERVAL);
      };

      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data as string) as WsMessage;
          handleMessage(data);
        } catch {
          /* ignore non-JSON messages */
        }
      };

      ws.onclose = () => {
        clearInterval(pingRef.current);
        wsRef.current = null;
        if (!mountedRef.current) return;

        setStatus("disconnected");

        const delay = Math.min(
          RECONNECT_BASE * 2 ** retryRef.current,
          RECONNECT_MAX,
        );
        retryRef.current += 1;
        setTimeout(connect, delay);
      };

      ws.onerror = () => {
        ws.close();
      };
    }

    connect();

    return () => {
      mountedRef.current = false;
      clearInterval(pingRef.current);
      if (wsRef.current) {
        wsRef.current.onclose = null;
        wsRef.current.close();
        wsRef.current = null;
      }
      setStatus("disconnected");
    };
  }, [addAlert, setStatus, queryClient]);
}
