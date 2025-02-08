package routes

import (
	"strings"
	acme_http "wiredshield/modules/db/acme"
	errorpages "wiredshield/pages/error"

	"github.com/valyala/fasthttp"
)

func ACMEChallenge(ctx *fasthttp.RequestCtx) {
	var token = strings.Split(string(ctx.Path()), "/")[len(strings.Split(string(ctx.Path()), "/"))-1]

	// get the challenge from db
	httpChallenge, err := acme_http.GetHttpChallenge(token)
	if err != nil {
		if strings.Contains(err.Error(), "MDB_NOTFOUND") {
			errorPage := errorpages.ErrorPage{Code: 404, Message: errorpages.Error604}
			ctx.SetStatusCode(fasthttp.StatusNotFound)
			ctx.Response.Header.Set("Content-Type", "text/html")
			ctx.SetBodyString(errorPage.ToHTML())
			return
		}

		errorPage := errorpages.ErrorPage{Code: 500, Message: errorpages.Error500}
		errorPage.Message = append(errorPage.Message, err.Error())

		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		ctx.Response.Header.Set("Content-Type", "text/html")
		ctx.SetBodyString(errorPage.ToHTML())
		return
	}

	// return the challenge
	ctx.SetContentType("text/plain")
	ctx.SetBodyString(httpChallenge.Token)
}
