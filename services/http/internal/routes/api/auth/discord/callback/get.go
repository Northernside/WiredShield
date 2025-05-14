package api_auth_discord_callback

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"wired/modules/env"
	"wired/modules/jwt"
	"wired/modules/logger"
	"wired/modules/pages"
	"wired/modules/postgresql"
	"wired/modules/types"
)

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope"`
}

func Get(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	code := r.URL.Query().Get("code")

	if code == "" {
		errorHtml(w, http.StatusBadRequest, []string{"Missing code parameter"})
		return
	}

	clientId := env.GetEnv("DISCORD_CLIENT_ID", "")
	clientSecret := env.GetEnv("DISCORD_CLIENT_SECRET", "")
	redirectUri := env.GetEnv("DISCORD_REDIRECT_URI", "")
	body := fmt.Sprintf("client_id=%s&client_secret=%s&grant_type=authorization_code&code=%s&redirect_uri=%s", clientId, clientSecret, code, redirectUri)

	req, err := http.NewRequest(http.MethodPost, "https://discord.com/api/v8/oauth2/token", bytes.NewBufferString(body))
	if err != nil {
		logger.Println("Failed to create request: ", err)
		errorHtml(w, http.StatusInternalServerError, []string{"Failed to create request:", err.Error()})
		return
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		errorHtml(w, http.StatusInternalServerError, []string{"(2) Failed to exchange code for token: ", err.Error(), "", fmt.Sprintf("Status Code: %d", resp.StatusCode)})
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		errorHtml(w, http.StatusInternalServerError, []string{"(2) Failed to exchange code for token: ", string(bodyBytes), "", fmt.Sprintf("Status Code: %d", resp.StatusCode)})
		return
	}

	token := tokenResponse{}
	err = json.NewDecoder(resp.Body).Decode(&token)
	if err != nil {
		logger.Println("Failed to decode token response: ", err)
		errorHtml(w, http.StatusInternalServerError, []string{"Failed to decode token response", err.Error()})
		return
	}

	req, err = http.NewRequest(http.MethodGet, "https://discord.com/api/v9/users/@me", nil)
	if err != nil {
		logger.Println("Failed to create request: ", err)
		errorHtml(w, http.StatusInternalServerError, []string{"Failed to create request", err.Error()})
		return
	}
	req.Header.Set("Authorization", token.TokenType+" "+token.AccessToken)

	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		logger.Println("Failed to get user info: ", err)
		errorHtml(w, http.StatusInternalServerError, []string{"Failed to get user info", err.Error()})
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		logger.Println("Failed to get user info: ", string(bodyBytes))
		errorHtml(w, http.StatusInternalServerError, []string{"Failed to get user info", string(bodyBytes)})
		return
	}

	account := &types.User{}
	err = json.NewDecoder(resp.Body).Decode(account)
	if err != nil {
		logger.Println("Failed to decode user info: ", err)
		errorHtml(w, http.StatusInternalServerError, []string{"Failed to decode user info", err.Error()})
		return
	}

	jwtToken, err := jwt.CreateToken(account.Id)
	if err != nil {
		logger.Println("Failed to create JWT token: ", err)
		errorHtml(w, http.StatusInternalServerError, []string{"Failed to create JWT token", err.Error()})
		return
	}

	err = postgresql.CreateOrUpdateUser(account)
	if err != nil {
		logger.Println("Failed to create or update user: ", err)
		errorHtml(w, http.StatusInternalServerError, []string{"Failed to create or update user", err.Error()})
		return
	}

	http.Redirect(w, r, fmt.Sprintf("%s/dash/api/auth?token="+jwtToken, env.GetEnv("SERVICE_URL", "")), http.StatusFound)
}

func errorHtml(w http.ResponseWriter, code int, messages []string) {
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(code)
	w.Write(pages.ErrorPages[700].Rerender(code, messages))
}
