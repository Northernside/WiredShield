package http_internal

import (
	"net/http"
	"path/filepath"
	"strings"
	"wired/modules/env"
	"wired/modules/pages"
	api_auth "wired/services/http/internal/routes/api/auth"
	api_auth_discord "wired/services/http/internal/routes/api/auth/discord"
	api_auth_discord_callback "wired/services/http/internal/routes/api/auth/discord/callback"
	api_domains "wired/services/http/internal/routes/api/domains"
	api_domains_records "wired/services/http/internal/routes/api/domains/records"
)

type Route struct {
	Method string
	Path   string
}

var (
	dashboardDir string
	staticRoutes = make(map[string]string)
	funcRoutes   = make(map[Route]func(http.ResponseWriter, *http.Request))
)

func PostStart() {
	dashboardDir = filepath.Join(env.GetEnv("PUBLIC_DIR", ""), "dashboard")
	staticRoutes = map[string]string{
		"/dash":          filepath.Join(dashboardDir, "index.html"),
		"/dash/domain/*": filepath.Join(dashboardDir, "domain", "index.html"),
	}

	funcRoutes = map[Route]func(http.ResponseWriter, *http.Request){
		{Method: http.MethodGet, Path: "/dash/api/auth"}:                  api_auth.Get,
		{Method: http.MethodGet, Path: "/dash/api/auth/discord"}:          api_auth_discord.Get,
		{Method: http.MethodGet, Path: "/dash/api/auth/discord/callback"}: api_auth_discord_callback.Get,
		{Method: http.MethodGet, Path: "/dash/api/domains"}:               api_domains.Get,
		{Method: http.MethodGet, Path: "/dash/api/domains/records"}:       api_domains_records.Get,
	}

	assetRoutes := []struct {
		prefix string
		dir    string
	}{
		{prefix: "/dash/assets/", dir: "assets"},
		{prefix: "/dash/js/", dir: "js"},
		{prefix: "/dash/css/", dir: "css"},
	}

	for _, route := range assetRoutes {
		prefix, dir := route.prefix, route.dir
		fileServer := http.FileServer(http.Dir(filepath.Join(dashboardDir, dir)))

		funcRoutes[Route{Method: http.MethodGet, Path: prefix + "*"}] = func(w http.ResponseWriter, r *http.Request) {
			http.StripPrefix(prefix, fileServer).ServeHTTP(w, r)
		}
	}

	api_auth.WhitelistedIds = strings.Split(env.GetEnv("WHITELISTED_IDS", ""), ",")
}

func HandleWiredRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		w.WriteHeader(http.StatusNoContent)
		return
	}

	for route, handler := range funcRoutes {
		match, _ := filepath.Match(route.Path, r.URL.Path)
		if route.Method == r.Method && match {
			handler(w, r)
			return
		}
	}

	for route, file := range staticRoutes {
		if match, _ := filepath.Match(route, r.URL.Path); match {
			http.ServeFile(w, r, file)
			return
		}
	}

	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusNotFound)
	w.Write(pages.ErrorPages[604].Html)
}
