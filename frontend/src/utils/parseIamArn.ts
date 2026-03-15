export type IamArnType =
  | "root"
  | "user"
  | "role"
  | "policy"
  | "analyzer"
  | "pwpolicy"
  | "unknown";

export interface ParsedIamArn {
  type: IamArnType;
  id: string;
  accountId?: string;
}

/**
 * Parses an IAM ARN into its component type and identifier.
 * Handles all IAM resource shapes used by CloudLine checks.
 */
export function parseIamArn(resource: string): ParsedIamArn {
  const match = resource.match(
    /^arn:aws:iam::(\d*):(.+)$/,
  );
  if (!match) {
    return { type: "unknown", id: resource };
  }
  const [, accountId, rest] = match;

  if (rest === "root") {
    return { type: "root", id: "root", accountId };
  }
  if (rest === "password-policy") {
    return {
      type: "pwpolicy",
      id: "password-policy",
      accountId,
    };
  }

  const slashIdx = rest.indexOf("/");
  if (slashIdx === -1) {
    return { type: "unknown", id: rest, accountId };
  }

  const typePart = rest.slice(0, slashIdx);
  const namePart = rest.slice(slashIdx + 1);

  switch (typePart) {
    case "user":
      return { type: "user", id: namePart, accountId };
    case "role":
      return { type: "role", id: namePart, accountId };
    case "policy":
      return { type: "policy", id: namePart, accountId };
    case "access-analyzer":
      return { type: "analyzer", id: namePart, accountId };
    default:
      return { type: "unknown", id: namePart, accountId };
  }
}
