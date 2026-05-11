import { z } from "zod";

export const ZOAuthLoginResponse = z.object({
  auth_url: z.string().url(),
  state: z.string(),
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
