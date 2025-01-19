package routes

import (
	"encoding/json"
	"wiredshield/modules/db"
	pages "wiredshield/pages"

	"github.com/valyala/fasthttp"
)

func GetDomains(ctx *fasthttp.RequestCtx) {
	domains, _ := db.GetAllDomains()
	ctx.Response.Header.Set("Content-Type", "application/json")
	ctx.SetStatusCode(fasthttp.StatusOK)
	jsonDomains, err := json.Marshal(domains)
	if err != nil {
		var errorLines []string
		errorLines = append(errorLines, pages.Error500...)
		errorLines = append(errorLines, err.Error())
		errorPage := pages.ErrorPage{Code: 500, Message: errorLines}
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		ctx.Response.Header.Set("Content-Type", "text/html")
		ctx.SetBodyString(errorPage.ToHTML())
		return
	}

	ctx.SetBody(jsonDomains)
}
