package routes

import (
	"fmt"
	"wiredshield/modules/env"

	"github.com/valyala/fasthttp"
)

func AuthDiscord(ctx *fasthttp.RequestCtx) {
	redirectURL := fmt.Sprintf("https://discord.com/oauth2/authorize?client_id=%s&response_type=code&redirect_uri=%s&scope=identify", env.GetEnv("DISCORD_CLIENT_ID", ""), env.GetEnv("DISCORD_REDIRECT_URI", ""))
	ctx.Redirect(redirectURL, fasthttp.StatusFound)
}
