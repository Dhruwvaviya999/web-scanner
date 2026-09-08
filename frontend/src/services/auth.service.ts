import { apiClient } from "@/lib/api-client";
import type { MessageResponse } from "@/types/api";
import type { AuthResponse, LoginPayload, RegisterPayload, User } from "@/types/user";

export const authService = {
  async register(payload: RegisterPayload): Promise<AuthResponse> {
    const { data } = await apiClient.post<AuthResponse>("/auth/register", payload);
    return data;
  },

  async login(payload: LoginPayload): Promise<AuthResponse> {
    const { data } = await apiClient.post<AuthResponse>("/auth/login", payload);
    return data;
  },

  async logout(): Promise<MessageResponse> {
    const { data } = await apiClient.post<MessageResponse>("/auth/logout");
    return data;
  },

  /** Resolve the session cookie into a user. Rejects with a 401 when signed out. */
  async me(): Promise<User> {
    const { data } = await apiClient.get<User>("/auth/me");
    return data;
  },
};
