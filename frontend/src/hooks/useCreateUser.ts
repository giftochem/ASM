import { useMutation, useQueryClient } from "@tanstack/react-query";
import { createUser, type CreateUserPayload } from "../api/users";
import { usersQueryKey } from "./useUsers";

export function useCreateUser() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (payload: CreateUserPayload) => createUser(payload),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: usersQueryKey });
    },
  });
}
