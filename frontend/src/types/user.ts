export interface User {
  id: string;
  name: string;
  email: string;
  created_at: string;
  updated_at: string;
}

export interface AuthResponse {
  /** The access token is delivered as an httpOnly cookie, never in this body. */
  user: User;
  expires_at: string;
  token_type: string;
}

export interface RegisterPayload {
  name: string;
  email: string;
  password: string;
  confirm_password: string;
}

export interface LoginPayload {
  email: string;
  password: string;
}

export interface UpdateProfilePayload {
  name: string;
}
