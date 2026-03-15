export interface WsConnectionOptions {
  onMessage?: (data: unknown) => void;
  onOpen?: () => void;
  onClose?: (event: CloseEvent) => void;
  onError?: (event: Event) => void;
}

export function createWsConnection(
  options: WsConnectionOptions = {},
): WebSocket {
  const wsUrl =
    import.meta.env.VITE_WS_URL || "/ws";
  const protocol = window.location.protocol === "https:"
    ? "wss:"
    : "ws:";
  const host = window.location.host;
  const fullUrl = wsUrl.startsWith("/")
    ? `${protocol}//${host}${wsUrl}/v1/events`
    : `${wsUrl}/v1/events`;

  const ws = new WebSocket(fullUrl);

  ws.onopen = () => {
    options.onOpen?.();
  };

  ws.onmessage = (event) => {
    try {
      const data = JSON.parse(event.data as string);
      options.onMessage?.(data);
    } catch {
      options.onMessage?.(event.data);
    }
  };

  ws.onclose = (event) => {
    options.onClose?.(event);
  };

  ws.onerror = (event) => {
    options.onError?.(event);
  };

  return ws;
}
