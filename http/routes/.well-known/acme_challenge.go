package routes

import (
	"wiredshield/modules/db"

	"github.com/valyala/fasthttp"
)

func ACMEChallenge(ctx *fasthttp.RequestCtx) {
	token := ctx.UserValue("tokeb").(string)

	// get the challenge from db
	httpChallenge, err := db.GetHttpChallenge(token)
	if err != nil {
		ctx.Error(err.Error(), fasthttp.StatusInternalServerError)
		return
	}

	// return the challenge
	ctx.SetContentType("text/plain")
	ctx.SetBodyString(httpChallenge.Token)
}
