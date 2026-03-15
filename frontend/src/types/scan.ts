export interface ScanResult {
  account_id: string;
  region: string;
  collection_timestamp: string;
  collection_mode: string;
  [key: string]: unknown;
}
