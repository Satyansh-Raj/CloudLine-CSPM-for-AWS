import { useQuery } from "@tanstack/react-query";
import { getMacieFindings } from "@/api";
import type {
  MacieFinding,
  MacieFindingsParams,
} from "@/types/macie";

export function useMacieFindings(
  params?: MacieFindingsParams,
) {
  return useQuery<MacieFinding[]>({
    queryKey: ["macie-findings", params],
    queryFn: () => getMacieFindings(params),
    refetchInterval: 60_000,
  });
}
