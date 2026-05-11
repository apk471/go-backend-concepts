package handler

import (
	"net/http"

	"github.com/apk471/go-boilerplate/internal/errs"
	"github.com/apk471/go-boilerplate/internal/middleware"
	"github.com/apk471/go-boilerplate/internal/server"
	"github.com/labstack/echo/v4"
)

type AuthHandler struct {
	Handler
}

type AuthMeResponse struct {
	UserID      string   `json:"user_id"`
	UserRole    string   `json:"user_role,omitempty"`
	Permissions []string `json:"permissions"`
}

func NewAuthHandler(s *server.Server) *AuthHandler {
	return &AuthHandler{
		Handler: NewHandler(s),
	}
}

func (h *AuthHandler) GetMe(c echo.Context) error {
	userID := middleware.GetUserID(c)
	if userID == "" {
		return errs.NewUnauthorizedError("Unauthorized", false)
	}

	response := AuthMeResponse{
		UserID:      userID,
		UserRole:    getStringContextValue(c, middleware.UserRoleKey),
		Permissions: getStringSliceContextValue(c, "permissions"),
	}

	return c.JSON(http.StatusOK, response)
}

func getStringContextValue(c echo.Context, key string) string {
	value, _ := c.Get(key).(string)
	return value
}

func getStringSliceContextValue(c echo.Context, key string) []string {
	value, ok := c.Get(key).([]string)
	if !ok {
		return []string{}
	}
	return value
}
