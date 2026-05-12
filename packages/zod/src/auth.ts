import { z } from "zod";

export const ZAuthMeResponse = z.object({
  user_id: z.string(),
  user_role: z.string().optional(),
  permissions: z.array(z.string()),
});

export const ZOAuthLoginResponse = z.object({
  auth_url: z.string().url(),
  state: z.string(),
});

export const ZServiceTokenResponse = z.object({
  authenticated: z.boolean(),
  auth_type: z.string(),
  message: z.string(),
});

export const ZOAuthTokenResponse = z.object({
  access_token: z.string(),
  token_type: z.string(),
  expires_in: z.number().optional(),
  refresh_token: z.string().optional(),
  scope: z.string().optional(),
  id_token: z.string().optional(),
  raw: z.unknown().optional(),
});
