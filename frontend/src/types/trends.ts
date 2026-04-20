export interface SnapshotPoint {
  date: string;
  active: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export interface TrendsHistoryResponse {
  snapshots: SnapshotPoint[];
}
