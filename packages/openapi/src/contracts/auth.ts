import { initContract } from "@ts-rest/core";
import { z } from "zod";
import {
  ZAuthMeResponse,
  ZCookieAuthResponse,
  ZOAuthLoginResponse,
  ZOAuthTokenResponse,
  ZServiceTokenResponse,
} from "@boilerplate/zod";
import { getSecurityMetadata } from "@/utils.js";

const c = initContract();

export const authContract = c.router({
  getMe: {
    summary: "Get authenticated user",
    path: "/api/v1/auth/me",
    method: "GET",
    description: "Get the currently authenticated user from the JWT bearer token",
    metadata: getSecurityMetadata(),
    responses: {
      200: ZAuthMeResponse,
    },
  },
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
  getServiceTokenStatus: {
    summary: "Validate service token",
    path: "/api/v1/auth/service-token/status",
    method: "GET",
    description:
      "Validate an opaque service token sent in the x-service-token header.",
    metadata: getSecurityMetadata({ securityType: "service" }),
    responses: {
      200: ZServiceTokenResponse,
    },
  },
  getCookieStatus: {
    summary: "Validate session cookie",
    path: "/api/v1/auth/cookie/status",
    method: "GET",
    description:
      "Validate cookie-based authentication using the auth_session cookie.",
    metadata: getSecurityMetadata({ securityType: "cookie" }),
    responses: {
      200: ZCookieAuthResponse,
    },
  },
});
