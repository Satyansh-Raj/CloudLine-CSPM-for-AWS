import { apiClient } from "./client";

export interface PolicyInfo {
  check_id: string;
  filename: string;
  package_name: string;
  domain: string;
  service: string;
  severity: string;
  path: string;
  rule_count: number;
  description: string;
}

export interface CreatePolicyRequest {
  check_id: string;
  name: string;
  domain: string;
  severity: string;
  description: string;
  input_field: string;
  resource_path: string;
  condition_field: string;
  condition_value: string;
  compliance_cis: string;
  compliance_nist: string;
  compliance_pci: string;
  remediation_id: string;
}

export interface PolicySource {
  check_id: string;
  filename: string;
  rego_code: string;
}

export async function getPolicies(): Promise<
  PolicyInfo[]
> {
  const { data } = await apiClient.get<{
    policies: PolicyInfo[];
  }>("/v1/policies");
  return data.policies;
}

export async function getPolicySource(
  checkId: string,
): Promise<PolicySource> {
  const { data } = await apiClient.get<PolicySource>(
    `/v1/policies/${checkId}/source`,
  );
  return data;
}

export async function createPolicy(
  req: CreatePolicyRequest,
): Promise<{ status: string; check_id: string }> {
  const { data } = await apiClient.post(
    "/v1/policies",
    req,
  );
  return data;
}

export interface CreateRawPolicyRequest {
  rego_code: string;
  domain: string;
  filename: string;
}

export async function createRawPolicy(
  req: CreateRawPolicyRequest,
): Promise<{
  status: string;
  check_ids: string[];
}> {
  const { data } = await apiClient.post(
    "/v1/policies/raw",
    req,
  );
  return data;
}

export async function deletePolicy(
  checkId: string,
): Promise<{ status: string }> {
  const { data } = await apiClient.delete(
    `/v1/policies/${checkId}`,
  );
  return data;
}
