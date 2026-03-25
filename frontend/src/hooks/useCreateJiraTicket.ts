import { useMutation, useQueryClient } from "@tanstack/react-query";
import { createJiraTicket, deleteJiraTicket } from "@/api";
import type { CreateTicketParams, JiraTicketResponse } from "@/types";

export function useCreateJiraTicket() {
  const queryClient = useQueryClient();

  return useMutation<JiraTicketResponse, Error, CreateTicketParams>({
    mutationFn: createJiraTicket,
    onSuccess: () => {
      queryClient.invalidateQueries({
        queryKey: ["violations"],
      });
    },
  });
}

export type DeleteTicketParams = Omit<
  CreateTicketParams,
  "summary" | "priority" | "labels"
>;

export function useDeleteJiraTicket() {
  const queryClient = useQueryClient();

  return useMutation<void, Error, DeleteTicketParams>({
    mutationFn: deleteJiraTicket,
    onSuccess: () => {
      queryClient.invalidateQueries({
        queryKey: ["violations"],
      });
    },
  });
}
