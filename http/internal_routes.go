package wiredhttps

import (
	"wiredshield/http/routes"

	"github.com/valyala/fasthttp"
)

func handleWiredShieldEndpoints(ctx *fasthttp.RequestCtx) {
	switch string(ctx.Path()) {
	case "/.wiredshield/proxy-auth":
		routes.ProxyAuth(ctx)
		return
	case "/.wiredshield/info":
		routes.Info(ctx)
		return
	default:
		ctx.Error("not found", fasthttp.StatusNotFound)
	}
}
