package api_auth

import (
	"net/http"

	"wired/modules/jwt"
	"wired/modules/pages"
)

var (
	WhitelistedIds = []string{}
)

func Get(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		http.Error(w, "Missing token parameter", http.StatusBadRequest)
		return
	}

	claims, err := jwt.ValidateToken(token)
	if err != nil {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	for _, id := range WhitelistedIds {
		if id == claims["discord_id"] {
			http.SetCookie(w, &http.Cookie{
				Name:   "token",
				Value:  token,
				Path:   "/",
				MaxAge: 604800, // 7 days
			})

			http.Redirect(w, r, "/dash", http.StatusFound)
			return
		}
	}

	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusForbidden)
	w.Write(pages.ErrorPages[603].Html)
}
