import type { IamArnType } from "@/utils/parseIamArn";

/**
 * Maps each IAM check ID to the ARN entity type it targets.
 * Used by iamGraphBuilder to assign violations to the correct
 * Level 1 node when the resource ARN cannot be parsed directly.
 */
export const IAM_CHECK_CATEGORIES: Record<string, IamArnType> = {
  iam_root_mfa: "root",
  iam_pwd_min_length: "pwpolicy",
  iam_pwd_uppercase: "pwpolicy",
  iam_pwd_lowercase: "pwpolicy",
  iam_pwd_numbers: "pwpolicy",
  iam_pwd_symbols: "pwpolicy",
  iam_pwd_reuse: "pwpolicy",
  iam_pwd_max_age: "pwpolicy",
  iam_user_mfa: "user",
  iam_root_access_keys: "root",
  iam_no_inline_policies: "user",
  iam_no_admin_access: "user",
  iam_key_rotation: "user",
  iam_inactive_user: "user",
  iam_access_analyzer: "analyzer",
  iam_no_wildcard_policy: "policy",
  iam_unused_keys: "user",
  iam_role_trust_wildcard: "role",
  iam_dual_access: "user",
  iam_support_role: "role",
};
