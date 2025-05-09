package api_auth_discord

import (
	"fmt"
	"net/http"
	"wired/modules/env"
)

func Get(w http.ResponseWriter, r *http.Request) {
	redirectURL := fmt.Sprintf("https://discord.com/oauth2/authorize?client_id=%s&response_type=code&redirect_uri=%s&scope=identify",
		env.GetEnv("DISCORD_CLIENT_ID", ""),
		env.GetEnv("DISCORD_REDIRECT_URI", ""))

	http.Redirect(w, r, redirectURL, http.StatusFound)
}
