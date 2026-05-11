import { z } from "zod";

export const ZAuthMeResponse = z.object({
  user_id: z.string(),
  user_role: z.string().optional(),
  permissions: z.array(z.string()),
});
