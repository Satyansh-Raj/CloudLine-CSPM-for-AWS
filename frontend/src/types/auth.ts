export type UserRole = "admin" | "operator" | "viewer";

export interface User {
  sk: string;
  email: string;
  full_name: string;
  role: UserRole;
  is_active: boolean;
  last_login: string | null;
<<<<<<< HEAD
=======
  reset_allowed?: boolean;
>>>>>>> 1134ea2 (Forget Password Error Fix)
}

export interface TokenPair {
  access_token: string;
  refresh_token: string;
  token_type: string;
}

export interface LoginCredentials {
  email: string;
  password: string;
}

export interface AuthContextValue {
  user: User | null;
  isLoading: boolean;
<<<<<<< HEAD
  login: (credentials: LoginCredentials) => Promise<void>;
=======
  login: (credentials: LoginCredentials) => Promise<User>;
>>>>>>> 1134ea2 (Forget Password Error Fix)
  logout: () => void;
  refreshMe: () => Promise<void>;
}
