import {
  render,
  screen,
  act,
  waitFor,
} from "@testing-library/react";
import { RegionProvider } from "../RegionContext";
import { useRegion } from "@/hooks/useRegion";

// --- mock getRegions API ---
vi.mock("@/api/regions", () => ({
  getRegions: vi.fn(),
}));

import { getRegions } from "@/api/regions";
const mockGetRegions =
  getRegions as ReturnType<typeof vi.fn>;

// --- consumer component ---
function RegionConsumer() {
  const ctx = useRegion();
  return (
    <div>
      <span data-testid="selected">
        {ctx.selectedRegion}
      </span>
      <span data-testid="regions">
        {ctx.regions.join(",")}
      </span>
      <span data-testid="loading">
        {String(ctx.isLoading)}
      </span>
      <button
        onClick={() =>
          ctx.setSelectedRegion("eu-west-1")
        }
      >
        select
      </button>
    </div>
  );
}

function renderProvider() {
  return render(
    <RegionProvider>
      <RegionConsumer />
    </RegionProvider>,
  );
}

describe("RegionContext", () => {
  afterEach(() => {
    vi.clearAllMocks();
  });

  it("renders children", () => {
    mockGetRegions.mockResolvedValue({
      regions: [],
      default: "",
    });
    renderProvider();
    expect(
      screen.getByTestId("selected"),
    ).toBeInTheDocument();
  });

  it("provides default selectedRegion as empty string",
    async () => {
      mockGetRegions.mockResolvedValue({
        regions: ["us-east-1"],
        default: "us-east-1",
      });
      renderProvider();
      // Before fetch resolves, default is ""
      expect(
        screen.getByTestId("selected"),
      ).toHaveTextContent("");
    });

  it("provides regions from API", async () => {
    mockGetRegions.mockResolvedValue({
      regions: ["ap-south-1", "eu-west-1"],
      default: "ap-south-1",
    });
    renderProvider();
    await waitFor(() => {
      expect(
        screen.getByTestId("regions"),
      ).toHaveTextContent("ap-south-1,eu-west-1");
    });
  });

  it("setSelectedRegion updates the value", async () => {
    mockGetRegions.mockResolvedValue({
      regions: ["ap-south-1", "eu-west-1"],
      default: "ap-south-1",
    });
    renderProvider();

    await act(async () => {
      screen.getByText("select").click();
    });

    expect(
      screen.getByTestId("selected"),
    ).toHaveTextContent("eu-west-1");
  });

  it("provides isLoading state", async () => {
    // Never-resolving promise to keep loading true
    mockGetRegions.mockReturnValue(
      new Promise(() => {}),
    );
    renderProvider();
    expect(
      screen.getByTestId("loading"),
    ).toHaveTextContent("true");
  });

  it("isLoading becomes false after fetch", async () => {
    mockGetRegions.mockResolvedValue({
      regions: ["us-east-1"],
      default: "us-east-1",
    });
    renderProvider();
    await waitFor(() => {
      expect(
        screen.getByTestId("loading"),
      ).toHaveTextContent("false");
    });
  });

  it("handles fetch error gracefully", async () => {
    mockGetRegions.mockRejectedValue(
      new Error("Network error"),
    );
    renderProvider();
    await waitFor(() => {
      expect(
        screen.getByTestId("loading"),
      ).toHaveTextContent("false");
    });
    // regions stays empty
    expect(
      screen.getByTestId("regions"),
    ).toHaveTextContent("");
  });
});
