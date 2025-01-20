package wiredhttps

import (
	"fmt"
	"strings"
	internal_routes "wiredshield/http/routes/.wiredshield"
	auth_routes "wiredshield/http/routes/api/auth"
	domain_routes "wiredshield/http/routes/api/domains"
	record_routes "wiredshield/http/routes/api/domains/records"
	"wiredshield/modules/jwt"
	dashpages "wiredshield/pages/dash"
	"wiredshield/services"

	"github.com/valyala/fasthttp"
)

var EndpointList = make(map[string]func(*fasthttp.RequestCtx))

func init() {
	passThroughHandler("/.wiredshield/proxy-auth", internal_routes.ProxyAuth, "GET")
	passThroughHandler("/.wiredshield/dns-update", internal_routes.DNSUpdate, "GET")
	passThroughHandler("/.wiredshield/ssl-update", internal_routes.SSLUpdate, "GET")
	passThroughHandler("/.wiredshield/info", internal_routes.Info, "GET")

	passThroughHandler("/.wiredshield/api/auth", auth_routes.Auth, "GET")
	passThroughHandler("/.wiredshield/api/auth/discord", auth_routes.AuthDiscord, "GET")
	passThroughHandler("/.wiredshield/api/auth/discord/callback", auth_routes.AuthDiscordCallback, "GET")

	userHandler("/.wiredshield/api/domains", domain_routes.GetDomains, "GET")
	userHandler("/.wiredshield/api/domains/records", record_routes.GetRecords, "GET")
	userHandler("/.wiredshield/api/domains/records", record_routes.GetRecords, "POST")

	userHandler("/.wiredshield/dash", PrepareResponse, "GET")
	userHandler("/.wiredshield/dash/domain/:domain", PrepareResponse, "GET")
	userHandler("/.wiredshield/css/global.css", PrepareResponse, "GET")
}

func PrepareResponse(ctx *fasthttp.RequestCtx) {
	cleanedPath := strings.Split(string(ctx.Path()), "?")[0]
	cleanedPath = strings.Split(cleanedPath, "#")[0]
	// remove any :params, check by each /, so e.g. /.wiredshield/dash/domain/northernsi.de will be /wiredshield/dash/domain because /.wiredshield/dash/domain/northernsi.de originates from /wiredshield/dash/domain/:domain
	userPath := ctx.UserValue("path").(string)
	services.ProcessService.InfoLog(fmt.Sprintf("userPath: %s, cleanedPath: %s", userPath, cleanedPath))
	if _, ok := EndpointList[fmt.Sprintf("%s:%s", ctx.Method(), cleanedPath)]; !ok {
		// remove the :param from the path
		cleanedPath = strings.Split(cleanedPath, "/"+strings.Split(userPath, "/")[strings.Count(userPath, "/")])[0]
	}

	// remove last / if there is one
	cleanedPath = strings.TrimSuffix(cleanedPath, "/")

	html, code := dashpages.PageResponse(cleanedPath)
	ctx.SetStatusCode(code)
	if strings.HasSuffix(cleanedPath, ".css") {
		ctx.SetContentType("text/css")
	} else {
		ctx.SetContentType("text/html")
	}

	ctx.SetBodyString(html)
}

func passThroughHandler(path string, handler fasthttp.RequestHandler, method string) {
	EndpointList[fmt.Sprintf("%s:%s", method, path)] = func(ctx *fasthttp.RequestCtx) {
		ctx.SetUserValue("path", path)
		if string(ctx.Method()) != method {
			ctx.Response.Header.Set("Content-Type", "application/json")
			ctx.SetStatusCode(fasthttp.StatusMethodNotAllowed)
			ctx.SetBody([]byte(`{"message": "Method not allowed"}`))
			return
		}

		handler(ctx)
	}
}

func userHandler(path string, handler fasthttp.RequestHandler, method string) {
	EndpointList[fmt.Sprintf("%s:%s", method, path)] = func(ctx *fasthttp.RequestCtx) {
		ctx.SetUserValue("path", path)
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
			services.ProcessService.InfoLog(fmt.Sprintf("matched: %s", k))
			return v, true
		}
	}

	return nil, false
}

func matchPattern(pattern, path string) (bool, map[string]string) {
	// remove everything before the first : including the : itself
	pattern = pattern[strings.Index(pattern, ":")+1:]
	path = path[strings.Index(path, ":")+1:]

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
