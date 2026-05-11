import { initContract } from "@ts-rest/core";
import { ZAuthMeResponse } from "@boilerplate/zod";
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
});
