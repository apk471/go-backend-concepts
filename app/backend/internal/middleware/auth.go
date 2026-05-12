package middleware

import (
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/apk471/go-boilerplate/internal/errs"
	"github.com/apk471/go-boilerplate/internal/server"
	"github.com/clerk/clerk-sdk-go/v2"
	clerkhttp "github.com/clerk/clerk-sdk-go/v2/http"
	"github.com/labstack/echo/v4"
)

type AuthMiddleware struct {
	server *server.Server
}

const SessionCookieName = "auth_session"

func NewAuthMiddleware(s *server.Server) *AuthMiddleware {
	return &AuthMiddleware{
		server: s,
	}
}

func (auth *AuthMiddleware) RequireAuth(next echo.HandlerFunc) echo.HandlerFunc {
	return echo.WrapMiddleware(
		clerkhttp.WithHeaderAuthorization(
			clerkhttp.AuthorizationFailureHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				start := time.Now()

				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)

				response := map[string]string{
					"code":     "UNAUTHORIZED",
					"message":  "Unauthorized",
					"override": "false",
					"status":   "401",
				}

				if err := json.NewEncoder(w).Encode(response); err != nil {
					auth.server.Logger.Error().Err(err).Str("function", "RequireAuth").Dur(
						"duration", time.Since(start)).Msg("failed to write JSON response")
				} else {
					auth.server.Logger.Error().Str("function", "RequireAuth").Dur("duration", time.Since(start)).Msg(
						"could not get session claims from context")
				}
			}))))(func(c echo.Context) error {
		start := time.Now()
		claims, ok := clerk.SessionClaimsFromContext(c.Request().Context())

		if !ok {
			auth.server.Logger.Error().
				Str("function", "RequireAuth").
				Str("request_id", GetRequestID(c)).
				Dur("duration", time.Since(start)).
				Msg("could not get session claims from context")
			return errs.NewUnauthorizedError("Unauthorized", false)
		}

		c.Set("user_id", claims.Subject)
		c.Set("user_role", claims.ActiveOrganizationRole)
		c.Set("permissions", claims.Claims.ActiveOrganizationPermissions)

		auth.server.Logger.Info().
			Str("function", "RequireAuth").
			Str("user_id", claims.Subject).
			Str("request_id", GetRequestID(c)).
			Dur("duration", time.Since(start)).
			Msg("user authenticated successfully")

		return next(c)
	})
}

func (auth *AuthMiddleware) RequireServiceToken(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		configuredToken := auth.server.Config.Auth.ServiceToken
		if configuredToken == "" {
			auth.server.Logger.Error().
				Str("function", "RequireServiceToken").
				Str("request_id", GetRequestID(c)).
				Msg("service token authentication is not configured")
			return errs.NewUnauthorizedError("Service token authentication is not configured", false)
		}

		token := c.Request().Header.Get("x-service-token")
		if token == "" {
			token = strings.TrimPrefix(c.Request().Header.Get("Authorization"), "Bearer ")
		}

		if token == "" || subtle.ConstantTimeCompare([]byte(token), []byte(configuredToken)) != 1 {
			auth.server.Logger.Warn().
				Str("function", "RequireServiceToken").
				Str("request_id", GetRequestID(c)).
				Msg("invalid service token")
			return errs.NewUnauthorizedError("Invalid service token", false)
		}

		c.Set("auth_type", "service_token")

		return next(c)
	}
}

func (auth *AuthMiddleware) RequireSessionCookie(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		configuredToken := auth.server.Config.Auth.SessionCookieToken
		if configuredToken == "" {
			auth.server.Logger.Error().
				Str("function", "RequireSessionCookie").
				Str("request_id", GetRequestID(c)).
				Msg("cookie authentication is not configured")
			return errs.NewUnauthorizedError("Cookie authentication is not configured", false)
		}

		sessionCookie, err := c.Cookie(SessionCookieName)
		if err != nil || sessionCookie.Value == "" {
			auth.server.Logger.Warn().
				Str("function", "RequireSessionCookie").
				Str("request_id", GetRequestID(c)).
				Msg("missing session cookie")
			return errs.NewUnauthorizedError("Missing session cookie", false)
		}

		if subtle.ConstantTimeCompare([]byte(sessionCookie.Value), []byte(configuredToken)) != 1 {
			auth.server.Logger.Warn().
				Str("function", "RequireSessionCookie").
				Str("request_id", GetRequestID(c)).
				Msg("invalid session cookie")
			return errs.NewUnauthorizedError("Invalid session cookie", false)
		}

		c.Set("auth_type", "cookie")

		return next(c)
	}
}
