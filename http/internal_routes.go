package wiredhttps

import (
	internal_routes "wiredshield/http/routes/.wiredshield"
	auth_routes "wiredshield/http/routes/api/auth"
	domain_routes "wiredshield/http/routes/api/domains"
	"wiredshield/modules/jwt"

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
}

func passThroughHandler(path string, handler fasthttp.RequestHandler) {
	EndpointList[path] = handler
	fasthttp.ListenAndServe(path, func(ctx *fasthttp.RequestCtx) {
		handler(ctx)
	})
}

func userHandler(path string, handler fasthttp.RequestHandler, method string) {
	EndpointList[path] = handler
	fasthttp.ListenAndServe(path, func(ctx *fasthttp.RequestCtx) {
		if string(ctx.Method()) != method {
			ctx.Response.Header.Set("Content-Type", "application/json")
			ctx.SetStatusCode(fasthttp.StatusMethodNotAllowed)
			ctx.SetBody([]byte(`{"message": "Method not allowed"}`))
			return
		}

		authorization := string(ctx.Request.Header.Cookie("Authorization"))
		if authorization == "" {
			ctx.Response.Header.Set("Content-Type", "application/json")
			ctx.SetStatusCode(fasthttp.StatusUnauthorized)
			ctx.SetBody([]byte(`{"message": "Unauthorized"}`))
			return
		}

		token := authorization[6:] // @Northernside TODO: gotta add proper cookie parsing later
		claims, err := jwt.ValidateToken(token)
		if err != nil {
			ctx.Response.Header.Set("Content-Type", "application/json")
			ctx.SetStatusCode(fasthttp.StatusUnauthorized)
			ctx.SetBody([]byte(`{"message": "Unauthorized"}`))
			return
		}

		// routes.WhitelistedIds
		for _, id := range auth_routes.WhitelistedIds {
			if id == claims["discord_id"] {
				handler(ctx)
				return
			}
		}

		ctx.Response.Header.Set("Content-Type", "application/json")
		ctx.SetStatusCode(fasthttp.StatusUnauthorized)
		ctx.SetBody([]byte(`{"message": "Unauthorized"}`))
	})
}
