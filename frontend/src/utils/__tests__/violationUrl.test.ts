import {
  toViolationPath,
  fromViolationResource,
  toResolvedPath,
  fromResolvedResource,
} from "../violationUrl";

describe("toViolationPath", () => {
  it("encodes check_id and resource", () => {
    expect(
      toViolationPath("s3_01", "arn:aws:s3:::bucket"),
    ).toBe(
      "/violations/s3_01/arn%3Aaws%3As3%3A%3A%3Abucket",
    );
  });
});

describe("fromViolationResource", () => {
  it("decodes encoded resource", () => {
    expect(
      fromViolationResource(
        "arn%3Aaws%3As3%3A%3A%3Abucket",
      ),
    ).toBe("arn:aws:s3:::bucket");
  });
});

describe("toResolvedPath", () => {
  it("builds /resolved/:checkId/:resource", () => {
    expect(
      toResolvedPath("iam_root_mfa", "arn:aws:iam::root"),
    ).toBe(
      "/resolved/iam_root_mfa/arn%3Aaws%3Aiam%3A%3Aroot",
    );
  });

  it("encodes special characters", () => {
    const arn =
      "arn:aws:ec2:ap-south-1:832843292195:sg/sg-1";
    const result = toResolvedPath("ec2_no_open_ssh", arn);
    expect(result).toContain("/resolved/");
    expect(result).toContain(encodeURIComponent(arn));
  });
});

describe("fromResolvedResource", () => {
  it("decodes encoded resource", () => {
    expect(
      fromResolvedResource(
        "arn%3Aaws%3Aiam%3A%3Aroot",
      ),
    ).toBe("arn:aws:iam::root");
  });

  it("handles already-decoded string", () => {
    expect(
      fromResolvedResource("simple-resource"),
    ).toBe("simple-resource");
  });
});
