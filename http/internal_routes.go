package wiredhttps

import (
	"strings"
	internal_routes "wiredshield/http/routes/.wiredshield"
	pages_routes "wiredshield/http/routes/.wiredshield/pages"
	auth_routes "wiredshield/http/routes/api/auth"
	domain_routes "wiredshield/http/routes/api/domains"
	record_routes "wiredshield/http/routes/api/domains/records"
	"wiredshield/modules/jwt"
	"wiredshield/services"

	"github.com/valyala/fasthttp"
)

var EndpointList = make(map[string]func(*fasthttp.RequestCtx))

func init() {
	passThroughHandler("/.wiredshield/proxy-auth", internal_routes.ProxyAuth)
	passThroughHandler("/.wiredshield/dns-update", internal_routes.DNSUpdate)
	passThroughHandler("/.wiredshield/ssl-update", internal_routes.SSLUpdate)
	passThroughHandler("/.wiredshield/info", internal_routes.Info)

	passThroughHandler("/.wiredshield/api/auth", auth_routes.Auth)
	passThroughHandler("/.wiredshield/api/auth/discord", auth_routes.AuthDiscord)
	passThroughHandler("/.wiredshield/api/auth/discord/callback", auth_routes.AuthDiscordCallback)

	userHandler("/.wiredshield/api/domains", domain_routes.GetDomains, "GET")
	userHandler("/.wiredshield/api/domains/records", record_routes.GetRecords, "GET")

	userHandler("/.wiredshield/dash", pages_routes.GetDomainsOverview, "GET")
	userHandler("/.wiredshield/dash/domain/:domain", pages_routes.GetDomain, "GET")
}

func passThroughHandler(path string, handler fasthttp.RequestHandler) {
	EndpointList[path] = handler
}

func userHandler(path string, handler fasthttp.RequestHandler, method string) {
	// services.ProcessService.InfoLog("Registering user handler for " + path)
	EndpointList[path] = func(ctx *fasthttp.RequestCtx) {
		services.ProcessService.InfoLog("GET " + string(ctx.Path()))
		if string(ctx.Method()) != method {
			ctx.Response.Header.Set("Content-Type", "application/json")
			ctx.SetStatusCode(fasthttp.StatusMethodNotAllowed)
			ctx.SetBody([]byte(`{"message": "Method not allowed"}`))
			return
		}

		token := string(ctx.Request.Header.Cookie("token"))
		if token == "" {
			ctx.Response.Header.Set("Content-Type", "application/json")
			ctx.SetStatusCode(fasthttp.StatusUnauthorized)
			ctx.SetBody([]byte(`{"message": "Unauthorized"}`))
			return
		}

		claims, err := jwt.ValidateToken(token)
		if err != nil {
			ctx.Response.Header.Set("Content-Type", "application/json")
			ctx.SetStatusCode(fasthttp.StatusUnauthorized)
			ctx.SetBody([]byte(`{"message": "Unauthorized"}`))
			return
		}

		for _, id := range auth_routes.WhitelistedIds {
			if id == claims["discord_id"] {
				handler(ctx)
				return
			}
		}

		ctx.Response.Header.Set("Content-Type", "application/json")
		ctx.SetStatusCode(fasthttp.StatusUnauthorized)
		ctx.SetBody([]byte(`{"message": "Unauthorized"}`))
	}
}

func GetHandler(path string) (func(*fasthttp.RequestCtx), bool) {
	for k, v := range EndpointList {
		if ok, _ := matchPattern(k, path); ok {
			return v, true
		}
	}

	return nil, false
}

func matchPattern(pattern, path string) (bool, map[string]string) {
	patternParts := strings.Split(pattern, "/")
	pathParts := strings.Split(path, "/")

	if len(patternParts) != len(pathParts) {
		return false, nil
	}

	params := make(map[string]string)
	for i := range patternParts {
		if strings.HasPrefix(patternParts[i], ":") {
			params[patternParts[i][1:]] = pathParts[i]
		} else if patternParts[i] != pathParts[i] {
			return false, nil
		}
	}

	return true, params
}
