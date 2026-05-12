import { match } from "ts-pattern";

export const getSecurityMetadata = ({
  security = true,
  securityType = "bearer",
}: {
  security?: boolean;
  securityType?: "bearer" | "service" | "cookie";
} = {}) => {
  const openApiSecurity = match(securityType)
    .with("bearer", () => [
      {
        bearerAuth: [],
      },
    ])
    .with("service", () => [
      {
        "x-service-token": [],
      },
    ])
    .with("cookie", () => [
      {
        cookieAuth: [],
      },
    ])
    .exhaustive();

  return {
    ...(security && { openApiSecurity }),
  };
};
