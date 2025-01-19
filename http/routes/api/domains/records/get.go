package routes

import (
	"encoding/json"
	"wiredshield/modules/db"
	errorpages "wiredshield/pages/error"

	"github.com/valyala/fasthttp"
)

func GetRecords(ctx *fasthttp.RequestCtx) {
	list, err := db.GetRecordsByDomain(string(ctx.QueryArgs().Peek("domain")))
	if err != nil {
		var errorLines []string
		errorLines = append(errorLines, errorpages.Error500...)
		errorLines = append(errorLines, err.Error())
		errorPage := errorpages.ErrorPage{Code: 500, Message: errorLines}
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		ctx.Response.Header.Set("Content-Type", "text/html")
		ctx.SetBodyString(errorPage.ToHTML())
		return
	}

	ctx.Response.Header.Set("Content-Type", "application/json")
	ctx.SetStatusCode(fasthttp.StatusOK)
	jsonList, err := json.Marshal(list)
	if err != nil {
		var errorLines []string
		errorLines = append(errorLines, errorpages.Error500...)
		errorLines = append(errorLines, err.Error())
		errorPage := errorpages.ErrorPage{Code: 500, Message: errorLines}
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		ctx.Response.Header.Set("Content-Type", "text/html")
		ctx.SetBodyString(errorPage.ToHTML())
		return
	}

	ctx.SetBody(jsonList)
}
