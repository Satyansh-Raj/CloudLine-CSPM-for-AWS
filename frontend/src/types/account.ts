export interface TargetAccount {
  account_id: string;
  account_name: string;
  role_arn: string;
  external_id: string;
  regions: string[];
  is_active: boolean;
  added_at: string;
  last_scanned: string | null;
}

export interface CreateAccountPayload {
  account_id: string;
  account_name: string;
  role_arn: string;
  external_id?: string;
  regions?: string[];
}

export interface AccountContextValue {
  selectedAccount: string;
  accounts: TargetAccount[];
  isLoading: boolean;
  setSelectedAccount: (accountId: string) => void;
  refresh: () => void;
}
