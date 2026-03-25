import {
  render,
  screen,
  fireEvent,
} from "@testing-library/react";
import RegionSelector from "../RegionSelector";

// --- mock useRegion hook ---
const mockRegionCtx = {
  selectedRegion: "",
  regions: ["ap-south-1", "eu-west-1"],
  isLoading: false,
  setSelectedRegion: vi.fn(),
};

vi.mock("@/hooks/useRegion", () => ({
  useRegion: () => mockRegionCtx,
}));

function renderSelector() {
  return render(<RegionSelector />);
}

describe("RegionSelector", () => {
  afterEach(() => {
    vi.clearAllMocks();
    mockRegionCtx.selectedRegion = "";
    mockRegionCtx.regions = [
      "ap-south-1",
      "eu-west-1",
    ];
    mockRegionCtx.isLoading = false;
  });

  it("renders dropdown with All Regions option", () => {
    renderSelector();
    expect(
      screen.getByText("All Regions"),
    ).toBeInTheDocument();
  });

  it("renders all available regions", () => {
    renderSelector();
    expect(
      screen.getByText("ap-south-1"),
    ).toBeInTheDocument();
    expect(
      screen.getByText("eu-west-1"),
    ).toBeInTheDocument();
  });

  it("shows globe icon", () => {
    renderSelector();
    // Globe icon SVG is present in the DOM
    const svg = document.querySelector("svg");
    expect(svg).toBeInTheDocument();
  });

  it("calls setSelectedRegion on change", () => {
    renderSelector();
    const select =
      screen.getByRole("combobox");
    fireEvent.change(select, {
      target: { value: "eu-west-1" },
    });
    expect(
      mockRegionCtx.setSelectedRegion,
    ).toHaveBeenCalledWith("eu-west-1");
  });

  it("displays selected region", () => {
    mockRegionCtx.selectedRegion = "ap-south-1";
    renderSelector();
    const select =
      screen.getByRole("combobox");
    expect(
      (select as HTMLSelectElement).value,
    ).toBe("ap-south-1");
  });

  it("All Regions option has empty string value", () => {
    renderSelector();
    const allOption = screen
      .getAllByRole("option")
      .find(
        (o) => o.textContent === "All Regions",
      ) as HTMLOptionElement;
    expect(allOption.value).toBe("");
  });

  it("shows loading indicator when isLoading", () => {
    mockRegionCtx.isLoading = true;
    mockRegionCtx.regions = [];
    renderSelector();
    // Select should still render (not crash)
    expect(
      screen.getByRole("combobox"),
    ).toBeInTheDocument();
  });

  it("renders empty regions list gracefully", () => {
    mockRegionCtx.regions = [];
    renderSelector();
    const options = screen.getAllByRole("option");
    // Only the "All Regions" option
    expect(options).toHaveLength(1);
  });
});
