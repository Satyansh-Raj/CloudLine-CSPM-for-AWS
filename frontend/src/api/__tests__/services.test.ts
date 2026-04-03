import { vi } from "vitest";

const mockGet = vi.fn();
const mockPost = vi.fn();
const mockPut = vi.fn();

vi.mock("../client", () => ({
  apiClient: {
    get: (...args: unknown[]) => mockGet(...args),
    post: (...args: unknown[]) => mockPost(...args),
    put: (...args: unknown[]) => mockPut(...args),
  },
}));

import { getComplianceScore } from "../compliance";
import { getDriftAlerts } from "../drift";
import { getHealth } from "../health";
import { getIamGraph } from "../iamGraph";
import { getInventorySummary } from "../inventory";
import { getRiskScores, getRiskSummary } from "../risk";
import { triggerScan } from "../scans";
import { getViolations } from "../violations";
import { createWsConnection } from "../websocket";

beforeEach(() => {
  vi.clearAllMocks();
});

describe("compliance API", () => {
  it("getComplianceScore calls GET /v1/compliance/score", async () => {
    const mockData = { overall_score: 85 };
    mockGet.mockResolvedValue({ data: mockData });

    const result = await getComplianceScore();
    expect(mockGet).toHaveBeenCalledWith("/v1/compliance/score", {
      params: undefined,
    });
    expect(result).toEqual(mockData);
  });

  it("getComplianceScore passes account_id as query param", async () => {
    mockGet.mockResolvedValue({ data: { overall_score: 90 } });
    await getComplianceScore("111111111111");
    expect(mockGet).toHaveBeenCalledWith("/v1/compliance/score", {
      params: { account_id: "111111111111" },
    });
  });

  it("getComplianceScore passes undefined params when no account_id", async () => {
    mockGet.mockResolvedValue({ data: { overall_score: 90 } });
    await getComplianceScore(undefined);
    expect(mockGet).toHaveBeenCalledWith("/v1/compliance/score", {
      params: undefined,
    });
  });
});

describe("drift API", () => {
  it("getDriftAlerts calls GET /v1/drift/alerts", async () => {
    const mockData = { alerts: [] };
    mockGet.mockResolvedValue({ data: mockData });

    const result = await getDriftAlerts();
    expect(mockGet).toHaveBeenCalledWith("/v1/drift/alerts", {
      params: undefined,
    });
    expect(result).toEqual(mockData);
  });

  it("getDriftAlerts passes params", async () => {
    mockGet.mockResolvedValue({ data: { alerts: [] } });
    const params = { limit: 10 };

    await getDriftAlerts(params);
    expect(mockGet).toHaveBeenCalledWith("/v1/drift/alerts", { params });
  });
});

describe("health API", () => {
  it("getHealth calls GET /health", async () => {
    const mockData = { status: "ok" };
    mockGet.mockResolvedValue({ data: mockData });

    const result = await getHealth();
    expect(mockGet).toHaveBeenCalledWith("/health");
    expect(result).toEqual(mockData);
  });
});

describe("risk API", () => {
  it("getRiskScores calls GET /v1/risk/scores", async () => {
    const mockData = { scores: [] };
    mockGet.mockResolvedValue({ data: mockData });

    const result = await getRiskScores();
    expect(mockGet).toHaveBeenCalledWith("/v1/risk/scores", {
      params: undefined,
    });
    expect(result).toEqual(mockData);
  });

  it("getRiskScores passes params", async () => {
    mockGet.mockResolvedValue({ data: { scores: [] } });
    const params = { severity: "critical" };

    await getRiskScores(params);
    expect(mockGet).toHaveBeenCalledWith("/v1/risk/scores", { params });
  });

  it("getRiskSummary calls GET /v1/risk/summary", async () => {
    const mockData = { total: 5, critical: 1 };
    mockGet.mockResolvedValue({ data: mockData });

    const result = await getRiskSummary();
    expect(mockGet).toHaveBeenCalledWith("/v1/risk/summary");
    expect(result).toEqual(mockData);
  });
});

describe("scans API", () => {
  it("triggerScan calls POST /v1/scans", async () => {
    const mockData = { scan_id: "s1", status: "started" };
    mockPost.mockResolvedValue({ data: mockData });

    const result = await triggerScan();
    expect(mockPost).toHaveBeenCalledWith("/v1/scans", undefined, {
      params: undefined,
    });
    expect(result).toEqual(mockData);
  });

  it("triggerScan passes account_id as query param", async () => {
    mockPost.mockResolvedValue({
      data: { scan_id: "s2", status: "started" },
    });
    await triggerScan("111111111111");
    expect(mockPost).toHaveBeenCalledWith("/v1/scans", undefined, {
      params: { account_id: "111111111111" },
    });
  });
});

describe("violations API", () => {
  it("getViolations calls GET /v1/violations", async () => {
    const mockData = [{ check_id: "s3_block_public_acls" }];
    mockGet.mockResolvedValue({ data: mockData });

    const result = await getViolations();
    expect(mockGet).toHaveBeenCalledWith("/v1/violations", {
      params: undefined,
    });
    expect(result).toEqual(mockData);
  });

  it("getViolations passes filter params", async () => {
    mockGet.mockResolvedValue({ data: [] });
    const params = {
      severity: "critical",
      domain: "network",
    };

    await getViolations(params);
    expect(mockGet).toHaveBeenCalledWith("/v1/violations", { params });
  });

  it("getViolations passes account_id as query param", async () => {
    mockGet.mockResolvedValue({ data: [] });
    const params = { account_id: "111111111111" };
    await getViolations(params);
    expect(mockGet).toHaveBeenCalledWith("/v1/violations", { params });
  });
});

describe("inventory API", () => {
  it("getInventorySummary calls GET /v1/inventory/summary", async () => {
    const mockData = { total: 10, by_category: {} };
    mockGet.mockResolvedValue({ data: mockData });

    const result = await getInventorySummary();
    expect(mockGet).toHaveBeenCalledWith("/v1/inventory/summary", {
      params: undefined,
    });
    expect(result).toEqual(mockData);
  });

  it("getInventorySummary passes account_id as query param", async () => {
    mockGet.mockResolvedValue({ data: { total: 5 } });
    await getInventorySummary(undefined, "111111111111");
    expect(mockGet).toHaveBeenCalledWith("/v1/inventory/summary", {
      params: { account_id: "111111111111" },
    });
  });

  it("getInventorySummary passes region and account_id together", async () => {
    mockGet.mockResolvedValue({ data: { total: 3 } });
    await getInventorySummary("ap-south-1", "222222222222");
    expect(mockGet).toHaveBeenCalledWith("/v1/inventory/summary", {
      params: { region: "ap-south-1", account_id: "222222222222" },
    });
  });
});

describe("iamGraph API", () => {
  it("getIamGraph calls GET /v1/iam/graph", async () => {
    const mockData = { account_id: "123", users: [] };
    mockGet.mockResolvedValue({ data: mockData });

    const result = await getIamGraph();
    expect(mockGet).toHaveBeenCalledWith("/v1/iam/graph", {
      params: undefined,
    });
    expect(result).toEqual(mockData);
  });

  it("getIamGraph passes account_id as query param", async () => {
    mockGet.mockResolvedValue({ data: { account_id: "111", users: [] } });
    await getIamGraph("111111111111");
    expect(mockGet).toHaveBeenCalledWith("/v1/iam/graph", {
      params: { account_id: "111111111111" },
    });
  });

  it("getIamGraph passes undefined params when no account_id", async () => {
    mockGet.mockResolvedValue({ data: { account_id: "x", users: [] } });
    await getIamGraph(undefined);
    expect(mockGet).toHaveBeenCalledWith("/v1/iam/graph", {
      params: undefined,
    });
  });
});

describe("websocket API", () => {
  const originalWebSocket = globalThis.WebSocket;

  beforeEach(() => {
    class MockWS {
      url: string;
      onopen: ((ev: Event) => void) | null = null;
      onmessage: ((ev: MessageEvent) => void) | null = null;
      onclose: ((ev: CloseEvent) => void) | null = null;
      onerror: ((ev: Event) => void) | null = null;

      constructor(url: string) {
        this.url = url;
      }
    }
    globalThis.WebSocket = MockWS as unknown as typeof WebSocket;
  });

  afterEach(() => {
    globalThis.WebSocket = originalWebSocket;
  });

  it("creates connection with correct URL", () => {
    const ws = createWsConnection();
    expect(ws).toBeDefined();
    expect((ws as unknown as { url: string }).url).toContain("/v1/events");
  });

  it("calls onOpen callback", () => {
    const onOpen = vi.fn();
    const ws = createWsConnection({ onOpen });
    ws.onopen?.({} as Event);
    expect(onOpen).toHaveBeenCalled();
  });

  it("parses JSON messages", () => {
    const onMessage = vi.fn();
    const ws = createWsConnection({ onMessage });
    ws.onmessage?.({
      data: '{"type":"violation_new"}',
    } as MessageEvent);
    expect(onMessage).toHaveBeenCalledWith({
      type: "violation_new",
    });
  });

  it("passes raw data for non-JSON", () => {
    const onMessage = vi.fn();
    const ws = createWsConnection({ onMessage });
    ws.onmessage?.({
      data: "not-json",
    } as MessageEvent);
    expect(onMessage).toHaveBeenCalledWith("not-json");
  });

  it("calls onClose callback", () => {
    const onClose = vi.fn();
    const ws = createWsConnection({ onClose });
    const evt = new Event("close") as CloseEvent;
    ws.onclose?.(evt);
    expect(onClose).toHaveBeenCalled();
  });

  it("calls onError callback", () => {
    const onError = vi.fn();
    const ws = createWsConnection({ onError });
    const evt = new Event("error");
    ws.onerror?.(evt);
    expect(onError).toHaveBeenCalled();
  });
});
