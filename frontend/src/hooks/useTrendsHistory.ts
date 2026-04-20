import { useQuery } from "@tanstack/react-query";
import { getTrendsHistory } from "@/api/trends";
import type { SnapshotPoint } from "@/types";

export function useTrendsHistory(
  accountId: string | undefined,
  since: string,
): { snapshots: SnapshotPoint[]; isLoading: boolean } {
  const { data, isLoading } = useQuery({
    queryKey: ["trendsHistory", accountId, since],
    queryFn: () => getTrendsHistory(accountId!, since),
    enabled: !!accountId,
    staleTime: 60_000,
  });
  return {
    snapshots: data?.snapshots ?? [],
    isLoading,
  };
}
