import { apiClient } from "./client";
import type {
  Violation,
  JiraTicketResponse,
  CreateTicketParams,
} from "@/types";

export interface ViolationParams {
  severity?: string;
  domain?: string;
  status?: string;
  region?: string;
}

export async function getViolations(
  params?: ViolationParams,
): Promise<Violation[]> {
  const { data } = await apiClient.get<Violation[]>("/v1/violations", {
    params,
  });
  return data;
}

export async function createJiraTicket(
  params: CreateTicketParams,
): Promise<JiraTicketResponse> {
  const {
    account_id,
    region,
    check_id,
    resource_id,
    summary,
    priority,
    labels,
  } = params;
  // resource_id is an ARN that may contain slashes;
  // the backend uses {resource_id:path} so we pass
  // it as-is (no encodeURIComponent) to preserve
  // the full ARN path across multiple segments.
  const url =
    `/v1/violations` +
    `/${account_id}` +
    `/${region}` +
    `/${check_id}` +
    `/${resource_id}` +
    `/ticket`;
  const body: Record<string, unknown> = {};
  if (summary !== undefined) body.summary = summary;
  if (priority !== undefined) body.priority = priority;
  if (labels !== undefined) body.labels = labels;
  const { data } = await apiClient.post<JiraTicketResponse>(url, body);
  return data;
}

export async function deleteJiraTicket(
  params: Omit<CreateTicketParams, "summary" | "priority" | "labels">,
): Promise<void> {
  const { account_id, region, check_id, resource_id } = params;
  const url =
    `/v1/violations` +
    `/${account_id}` +
    `/${region}` +
    `/${check_id}` +
    `/${resource_id}` +
    `/ticket`;
  await apiClient.delete(url);
}
