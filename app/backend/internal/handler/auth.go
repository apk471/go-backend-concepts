package handler

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/apk471/go-boilerplate/internal/errs"
	"github.com/apk471/go-boilerplate/internal/middleware"
	"github.com/apk471/go-boilerplate/internal/server"
	"github.com/labstack/echo/v4"
)

const oauthStateCookieName = "oauth_state"

type AuthHandler struct {
	Handler
}

type AuthMeResponse struct {
	UserID      string   `json:"user_id"`
	UserRole    string   `json:"user_role,omitempty"`
	Permissions []string `json:"permissions"`
}

type OAuthSessionResponse struct {
	AuthURL string `json:"auth_url"`
	State   string `json:"state"`
}

type OAuthTokenResponse struct {
	AccessToken  string          `json:"access_token"`
	TokenType    string          `json:"token_type"`
	ExpiresIn    int             `json:"expires_in,omitempty"`
	RefreshToken string          `json:"refresh_token,omitempty"`
	Scope        string          `json:"scope,omitempty"`
	IDToken      string          `json:"id_token,omitempty"`
	Raw          json.RawMessage `json:"raw,omitempty"`
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

func (h *AuthHandler) StartOAuth(c echo.Context) error {
	oauthConfig := h.server.Config.Auth.OAuth
	if err := validateOAuthConfig(oauthConfig.ClientID, oauthConfig.AuthURL, oauthConfig.RedirectURL); err != nil {
		return err
	}

	state, err := newOAuthState()
	if err != nil {
		h.server.Logger.Error().Err(err).Msg("failed to generate oauth state")
		return errs.NewInternalServerError()
	}

	http.SetCookie(c.Response(), &http.Cookie{
		Name:     oauthStateCookieName,
		Value:    state,
		Path:     "/",
		MaxAge:   int((10 * time.Minute).Seconds()),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   h.server.Config.Primary.Env == "production",
	})

	authURL, err := buildOAuthAuthorizationURL(oauthConfig.AuthURL, oauthConfig.ClientID, oauthConfig.RedirectURL,
		oauthConfig.Scopes, state)
	if err != nil {
		return errs.NewBadRequestError("Invalid OAuth authorization URL", false, nil, nil, nil)
	}

	if c.QueryParam("response") == "json" {
		return c.JSON(http.StatusOK, OAuthSessionResponse{
			AuthURL: authURL,
			State:   state,
		})
	}

	return c.Redirect(http.StatusFound, authURL)
}

func (h *AuthHandler) CompleteOAuth(c echo.Context) error {
	oauthConfig := h.server.Config.Auth.OAuth
	if err := validateOAuthConfig(oauthConfig.ClientID, oauthConfig.AuthURL, oauthConfig.RedirectURL); err != nil {
		return err
	}
	if oauthConfig.ClientSecret == "" || oauthConfig.TokenURL == "" {
		return errs.NewBadRequestError("OAuth token exchange is not configured", false, nil, nil, nil)
	}

	code := c.QueryParam("code")
	state := c.QueryParam("state")
	if code == "" || state == "" {
		return errs.NewBadRequestError("OAuth callback requires code and state", false, nil, nil, nil)
	}

	stateCookie, err := c.Cookie(oauthStateCookieName)
	if err != nil || stateCookie.Value == "" || stateCookie.Value != state {
		return errs.NewUnauthorizedError("Invalid OAuth state", false)
	}

	http.SetCookie(c.Response(), &http.Cookie{
		Name:     oauthStateCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   h.server.Config.Primary.Env == "production",
	})

	tokenResponse, err := exchangeOAuthCode(oauthConfig.TokenURL, oauthConfig.ClientID, oauthConfig.ClientSecret,
		oauthConfig.RedirectURL, code)
	if err != nil {
		h.server.Logger.Error().Err(err).Msg("oauth token exchange failed")
		return errs.NewUnauthorizedError("OAuth token exchange failed", false)
	}

	return c.JSON(http.StatusOK, tokenResponse)
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

func validateOAuthConfig(clientID string, authURL string, redirectURL string) error {
	if clientID == "" || authURL == "" || redirectURL == "" {
		return errs.NewBadRequestError("OAuth authorization is not configured", false, nil, nil, nil)
	}
	return nil
}

func newOAuthState() (string, error) {
	randomBytes := make([]byte, 32)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(randomBytes), nil
}

func buildOAuthAuthorizationURL(authURL string, clientID string, redirectURL string, scopes string, state string) (string, error) {
	parsedURL, err := url.Parse(authURL)
	if err != nil {
		return "", err
	}

	query := parsedURL.Query()
	query.Set("response_type", "code")
	query.Set("client_id", clientID)
	query.Set("redirect_uri", redirectURL)
	query.Set("state", state)
	if scopes != "" {
		query.Set("scope", strings.ReplaceAll(scopes, ",", " "))
	}
	parsedURL.RawQuery = query.Encode()

	return parsedURL.String(), nil
}

func exchangeOAuthCode(tokenURL string, clientID string, clientSecret string, redirectURL string, code string) (OAuthTokenResponse, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("client_id", clientID)
	form.Set("client_secret", clientSecret)
	form.Set("redirect_uri", redirectURL)
	form.Set("code", code)

	request, err := http.NewRequest(http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return OAuthTokenResponse{}, err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Accept", "application/json")

	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return OAuthTokenResponse{}, err
	}
	defer response.Body.Close()

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return OAuthTokenResponse{}, err
	}

	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return OAuthTokenResponse{}, errs.NewUnauthorizedError("OAuth provider rejected authorization code", false)
	}

	var tokenResponse OAuthTokenResponse
	if err := json.Unmarshal(body, &tokenResponse); err != nil {
		return OAuthTokenResponse{}, err
	}
	tokenResponse.Raw = body

	return tokenResponse, nil
}
