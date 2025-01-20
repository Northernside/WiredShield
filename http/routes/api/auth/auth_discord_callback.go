package routes

import (
	"encoding/json"
	"fmt"

	"wiredshield/modules/env"
	"wiredshield/modules/jwt"
	"wiredshield/services"

	"github.com/valyala/fasthttp"
)

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope"`
}

type user struct {
	ID string `json:"id"`
}

func AuthDiscordCallback(ctx *fasthttp.RequestCtx) {
	ctx.Response.Header.Set("Content-Type", "application/json")
	code := string(ctx.QueryArgs().Peek("code"))

	if code == "" {
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		ctx.SetBody([]byte(`{"message": "No code provided"}`))
		return
	}

	clientId := env.GetEnv("DISCORD_CLIENT_ID", "")
	clientSecret := env.GetEnv("DISCORD_CLIENT_SECRET", "")
	redirectUri := env.GetEnv("DISCORD_REDIRECT_URI", "")
	body := fmt.Sprintf("client_id=%s&client_secret=%s&grant_type=authorization_code&code=%s&redirect_uri=%s", clientId, clientSecret, code, redirectUri)

	req := fasthttp.AcquireRequest()
	defer fasthttp.ReleaseRequest(req)
	req.SetRequestURI("https://discord.com/api/v8/oauth2/token")
	req.Header.SetMethod(fasthttp.MethodPost)
	req.Header.SetContentType("application/x-www-form-urlencoded")
	req.SetBodyString(body)

	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseResponse(resp)
	err := fasthttp.Do(req, resp)
	if err != nil {
		services.GetService("https").ErrorLog(err.Error())
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		ctx.SetBody([]byte(`{"message": "Failed to exchange code for token", "error": "` + err.Error() + `"}`))
		return
	}

	if resp.StatusCode() != fasthttp.StatusOK {
		services.GetService("https").ErrorLog(err.Error())
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		ctx.SetBody([]byte(`{"message": "Failed to exchange code for token", "error": "` + string(resp.Body()) + `"}`))
		return
	}

	token := tokenResponse{}
	err = json.Unmarshal(resp.Body(), &token)
	if err != nil {
		services.GetService("https").ErrorLog(err.Error())
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		ctx.SetBody([]byte(`{"message": "Failed to decode token", "error": "` + err.Error() + `"}`))
		return
	}

	req.Reset()
	req.SetRequestURI("https://discord.com/api/v8/users/@me")
	req.Header.SetMethod(fasthttp.MethodGet)
	req.Header.Set("Authorization", token.TokenType+" "+token.AccessToken)

	err = fasthttp.Do(req, resp)
	if err != nil {
		services.GetService("https").ErrorLog(err.Error())
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		ctx.SetBody([]byte(`{"message": "Failed to get user info", "error": "` + err.Error() + `"}`))
		return
	}

	if resp.StatusCode() != fasthttp.StatusOK {
		services.GetService("https").ErrorLog(err.Error())
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		ctx.SetBody([]byte(`{"message": "Failed to get user info", "error": "` + string(resp.Body()) + `"}`))
		return
	}

	user := user{}
	err = json.Unmarshal(resp.Body(), &user)
	if err != nil {
		services.GetService("https").ErrorLog(err.Error())
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		ctx.SetBody([]byte(`{"message": "Failed to decode user info", "error": "` + err.Error() + `"}`))
		return
	}

	jwtToken, err := jwt.CreateToken(user.ID)
	if err != nil {
		services.GetService("https").ErrorLog(err.Error())
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		ctx.SetBody([]byte(`{"message": "Failed to create JWT token", "error": "` + err.Error() + `"}`))
		return
	}

	ctx.Redirect(fmt.Sprintf("%s/.wiredshield/api/auth?token="+jwtToken, env.GetEnv("SERVICE_URL", "")), fasthttp.StatusFound)
}
