package wiredhttps

import (
	internal_routes "wiredshield/http/routes/.wiredshield"
	routes "wiredshield/http/routes/api"
	"wiredshield/modules/jwt"

	"github.com/valyala/fasthttp"
)

var EndpointList map[string]func(*fasthttp.RequestCtx)

func init() {
	passThroughHandler("/.wiredshield/proxy-auth", internal_routes.ProxyAuth)
	passThroughHandler("/.wiredshield/dns-update", internal_routes.DNSUpdate)
	passThroughHandler("/.wiredshield/ssl-update", internal_routes.SSLUpdate)
	passThroughHandler("/.wiredshield/info", internal_routes.Info)

	passThroughHandler("/api/auth", routes.Auth)
	passThroughHandler("/api/auth/discord", routes.AuthDiscord)
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
		for _, id := range routes.WhitelistedIds {
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
