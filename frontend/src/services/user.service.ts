import { apiClient } from "@/lib/api-client";
import type { UpdateProfilePayload, User } from "@/types/user";

export const userService = {
  async getProfile(): Promise<User> {
    const { data } = await apiClient.get<User>("/users/me");
    return data;
  },

  async updateProfile(payload: UpdateProfilePayload): Promise<User> {
    const { data } = await apiClient.patch<User>("/users/me", payload);
    return data;
  },
};
