package routes

import (
	"encoding/json"
	"wiredshield/modules/db"
	errorpages "wiredshield/pages/error"
	"wiredshield/services"

	"github.com/valyala/fasthttp"
)

func GetDomains(ctx *fasthttp.RequestCtx) {
	domains, _ := db.GetAllDomains()
	ctx.Response.Header.Set("Content-Type", "application/json")
	ctx.SetStatusCode(fasthttp.StatusOK)
	jsonDomains, err := json.Marshal(domains)
	if err != nil {
		var errorLines []string
		errorLines = append(errorLines, errorpages.Error500...)
		errorLines = append(errorLines, err.Error())
		errorPage := errorpages.ErrorPage{Code: 500, Message: errorLines}

		services.GetService("https").ErrorLog(err.Error())
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		ctx.Response.Header.Set("Content-Type", "text/html")
		ctx.SetBodyString(errorPage.ToHTML())
		return
	}

	ctx.SetBody(jsonDomains)
}
