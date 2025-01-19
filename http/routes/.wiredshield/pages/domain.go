package routes

import (
	"strings"
	dashpages "wiredshield/pages/dash"

	"github.com/valyala/fasthttp"
)

func GetDomain(ctx *fasthttp.RequestCtx) {
	cleanedPath := strings.Split(string(ctx.Path()), "?")[0]
	cleanedPath = strings.Split(cleanedPath, "#")[0]

	html, code := dashpages.PageResponse(cleanedPath)
	ctx.SetStatusCode(code)
	ctx.SetContentType("text/html")
	ctx.SetBodyString(html)
}
