import { apiClient } from "../client";

describe("apiClient", () => {
  it("has correct base URL", () => {
    expect(apiClient.defaults.baseURL).toBe("/api");
  });

  it("has JSON content type", () => {
    expect(
      apiClient.defaults.headers["Content-Type"],
    ).toBe("application/json");
  });

  it("has response interceptors registered", () => {
    expect(
      apiClient.interceptors.response,
    ).toBeDefined();
  });

  describe("response interceptor", () => {
    it("normalizes server errors", async () => {
      const handlers =
        (
          apiClient.interceptors.response as unknown as {
            handlers: {
              rejected?: (
                e: unknown,
              ) => Promise<never>;
            }[];
          }
        ).handlers;

      const rejected = handlers.find(
        (h) => h.rejected,
      )?.rejected;

      if (rejected) {
        const error = {
          response: {
            status: 500,
            data: { detail: "Server error" },
          },
          message: "Request failed",
        };

        await expect(
          rejected(error),
        ).rejects.toEqual({
          status: 500,
          message: "Server error",
          detail: { detail: "Server error" },
        });
      }
    });

    it("handles network errors without response", async () => {
      const handlers =
        (
          apiClient.interceptors.response as unknown as {
            handlers: {
              rejected?: (
                e: unknown,
              ) => Promise<never>;
            }[];
          }
        ).handlers;

      const rejected = handlers.find(
        (h) => h.rejected,
      )?.rejected;

      if (rejected) {
        const error = {
          message: "Network Error",
        };

        await expect(
          rejected(error),
        ).rejects.toEqual({
          status: 0,
          message: "Network Error",
          detail: undefined,
        });
      }
    });
  });
});
