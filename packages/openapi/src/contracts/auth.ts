import { initContract } from "@ts-rest/core";
import { z } from "zod";
import { ZOAuthLoginResponse, ZOAuthTokenResponse } from "@boilerplate/zod";

const c = initContract();

export const authContract = c.router({
  startOAuth: {
    summary: "Start OAuth login",
    path: "/api/v1/auth/oauth/login",
    method: "GET",
    description:
      "Start the OAuth authorization code flow. By default this redirects to the provider. Use response=json to get the authorization URL in OpenAPI.",
    query: z
      .object({
        response: z.literal("json").optional(),
      })
      .optional(),
    responses: {
      200: ZOAuthLoginResponse,
      302: z.unknown(),
    },
  },
  completeOAuth: {
    summary: "Complete OAuth callback",
    path: "/api/v1/auth/oauth/callback",
    method: "GET",
    description:
      "Complete the OAuth authorization code flow by exchanging code for provider tokens.",
    query: z.object({
      code: z.string(),
      state: z.string(),
    }),
    responses: {
      200: ZOAuthTokenResponse,
    },
  },
});
