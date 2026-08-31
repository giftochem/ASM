import { useQuery } from "@tanstack/react-query";
import { listUsers } from "../api/users";

export const usersQueryKey = ["users"] as const;

export function useUsers() {
  return useQuery({
    queryKey: usersQueryKey,
    queryFn: listUsers,
  });
}
