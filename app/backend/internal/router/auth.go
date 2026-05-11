package router

import (
	"github.com/apk471/go-boilerplate/internal/handler"
	"github.com/apk471/go-boilerplate/internal/middleware"
	"github.com/labstack/echo/v4"
)

func registerAuthRoutes(r *echo.Group, h *handler.Handlers, middlewares *middleware.Middlewares) {
	auth := r.Group("/auth")

	auth.GET("/oauth/login", h.Auth.StartOAuth)
	auth.GET("/oauth/callback", h.Auth.CompleteOAuth)
}
