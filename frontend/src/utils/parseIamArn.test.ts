import { describe, it, expect } from "vitest";
import { parseIamArn } from "./parseIamArn";

describe("parseIamArn", () => {
  it("parses root ARN", () => {
    expect(
      parseIamArn("arn:aws:iam::123456789012:root"),
    ).toEqual({
      type: "root",
      id: "root",
      accountId: "123456789012",
    });
  });

  it("parses user ARN", () => {
    expect(
      parseIamArn("arn:aws:iam::123456789012:user/alice"),
    ).toEqual({
      type: "user",
      id: "alice",
      accountId: "123456789012",
    });
  });

  it("parses role ARN", () => {
    expect(
      parseIamArn("arn:aws:iam::123:role/MyRole"),
    ).toEqual({
      type: "role",
      id: "MyRole",
      accountId: "123",
    });
  });

  it("parses policy ARN", () => {
    expect(
      parseIamArn("arn:aws:iam::123:policy/MyPolicy"),
    ).toEqual({
      type: "policy",
      id: "MyPolicy",
      accountId: "123",
    });
  });

  it("parses access-analyzer ARN", () => {
    expect(
      parseIamArn(
        "arn:aws:iam::123:access-analyzer/my-analyzer",
      ),
    ).toEqual({
      type: "analyzer",
      id: "my-analyzer",
      accountId: "123",
    });
  });

  it("parses password-policy ARN", () => {
    expect(
      parseIamArn("arn:aws:iam::123:password-policy"),
    ).toEqual({
      type: "pwpolicy",
      id: "password-policy",
      accountId: "123",
    });
  });

  it("returns unknown for non-ARN string", () => {
    expect(parseIamArn("not-an-arn")).toEqual({
      type: "unknown",
      id: "not-an-arn",
    });
  });

  it("handles empty account ID", () => {
    const result = parseIamArn("arn:aws:iam:::user/bob");
    expect(result.type).toBe("user");
    expect(result.id).toBe("bob");
    expect(result.accountId).toBe("");
  });

  it("returns unknown for unrecognised resource type", () => {
    const result = parseIamArn(
      "arn:aws:iam::123:unknown-type/foo",
    );
    expect(result.type).toBe("unknown");
    expect(result.id).toBe("foo");
  });

  it("returns unknown for bare unrecognised type (no slash)", () => {
    const result = parseIamArn("arn:aws:iam::123:someservice");
    expect(result.type).toBe("unknown");
    expect(result.id).toBe("someservice");
  });

  it("parses user with path prefix", () => {
    const result = parseIamArn(
      "arn:aws:iam::123:user/division/alice",
    );
    expect(result.type).toBe("user");
    expect(result.id).toBe("division/alice");
  });
});
