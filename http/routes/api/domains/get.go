package routes

import (
	"encoding/json"
	"wiredshield/modules/db"
	pages "wiredshield/pages"

	"github.com/valyala/fasthttp"
)

func GetDomains(ctx *fasthttp.RequestCtx) {
	domains, err := db.GetAllDomains()
	if err != nil {
		errorPage := pages.ErrorPage{Code: 500, Message: pages.Error500}
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		ctx.Response.Header.Set("Content-Type", "text/html")
		ctx.SetBodyString(errorPage.ToHTML())
		return
	}

	ctx.Response.Header.Set("Content-Type", "application/json")
	ctx.SetStatusCode(fasthttp.StatusOK)
	jsonDomains, err := json.Marshal(domains)
	if err != nil {
		errorPage := pages.ErrorPage{Code: 500, Message: pages.Error500}
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		ctx.Response.Header.Set("Content-Type", "text/html")
		ctx.SetBodyString(errorPage.ToHTML())
		return
	}

	ctx.SetBody(jsonDomains)
}
