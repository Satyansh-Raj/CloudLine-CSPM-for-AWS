export interface MacieFinding {
  finding_id: string;
  type: string;
  bucket_name: string;
  severity: string;
  category: string;
  count: number;
  first_observed_at: string;
  last_observed_at: string;
  region: string;
  account_id: string;
}

export interface MacieFindingsParams {
  bucket_name?: string;
  severity?: string;
  account_id?: string;
  limit?: number;
}
