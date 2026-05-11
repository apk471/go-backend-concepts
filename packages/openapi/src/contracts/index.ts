import { initContract } from "@ts-rest/core";
import { authContract } from "./auth.js";
import { healthContract } from "./health.js";

const c = initContract();

export const apiContract = c.router({
  Auth: authContract,
  Health: healthContract,
});
