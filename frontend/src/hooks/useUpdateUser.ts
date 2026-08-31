import { useMutation, useQueryClient } from "@tanstack/react-query";
import { updateUser, type UpdateUserPayload, type User } from "../api/users";
import { usersQueryKey } from "./useUsers";

export function useUpdateUser() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ userId, payload }: { userId: string; payload: UpdateUserPayload }) =>
      updateUser(userId, payload),
    onSuccess: (updated: User) => {
      // Patch the single row in place rather than refetching the whole
      // list — PATCH returns the full updated UserRead, so a refetch
      // would be a redundant round trip for data we already hold.
      queryClient.setQueryData<User[]>(usersQueryKey, (previous) =>
        previous ? previous.map((user) => (user.id === updated.id ? updated : user)) : previous,
      );
    },
  });
}
