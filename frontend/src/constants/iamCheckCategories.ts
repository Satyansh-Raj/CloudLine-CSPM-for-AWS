import type { IamArnType } from "@/utils/parseIamArn";

/**
 * Maps each IAM check ID to the ARN entity type it targets.
 * Used by iamGraphBuilder to assign violations to the correct
 * Level 1 node when the resource ARN cannot be parsed directly.
 */
export const IAM_CHECK_CATEGORIES: Record<string, IamArnType> = {
  iam_01: "root",
  iam_02: "pwpolicy",
  iam_03: "pwpolicy",
  iam_04: "pwpolicy",
  iam_05: "pwpolicy",
  iam_06: "pwpolicy",
  iam_07: "pwpolicy",
  iam_08: "pwpolicy",
  iam_09: "user",
  iam_10: "root",
  iam_11: "user",
  iam_12: "user",
  iam_13: "user",
  iam_14: "user",
  iam_15: "analyzer",
  iam_16: "policy",
  iam_17: "user",
  iam_18: "role",
  iam_19: "user",
  iam_20: "role",
};
