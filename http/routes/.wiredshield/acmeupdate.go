package routes

import (
	"fmt"
	"strconv"
	"time"
	acme_http "wiredshield/modules/db/acme"
	"wiredshield/modules/env"
	"wiredshield/modules/pgp"
	"wiredshield/services"
	"wiredshield/utils/b64"

	"github.com/valyala/fasthttp"
)

// endpoint is supposed to be used by the master server to update the acme http challenge details of the clients
func ACMEUpdate(ctx *fasthttp.RequestCtx) {
	// master auth logic
	var signature = string(ctx.Request.Header.Peek("signature"))
	var auth_message = string(ctx.Request.Header.Peek("auth_message"))
	if signature == "" || auth_message == "" {
		ctx.SetStatusCode(fasthttp.StatusUnauthorized)
		ctx.SetBodyString("UNAUTHORIZED v1")
		return
	}

	var partnerMaster string
	if env.GetEnv("CLIENT_NAME", "meow") == "woof" {
		partnerMaster = "meow"
	} else {
		partnerMaster = "woof"
	}

	partnerPub, err := pgp.LoadPublicKey(fmt.Sprintf("certs/%s-public.asc", partnerMaster))
	if err != nil {
		services.GetService("https").ErrorLog(err.Error())
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		ctx.SetBodyString("INTERNAL_SERVER_ERROR")
		return
	}

	b64Sig, err := b64.Decode(signature)
	if err != nil {
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		ctx.SetBodyString("BAD_REQUEST")
		return
	}

	b64SigStr := string(b64Sig)
	err = pgp.VerifySignature(auth_message, b64SigStr, partnerPub)
	if err != nil {
		ctx.SetStatusCode(fasthttp.StatusUnauthorized)
		ctx.SetBodyString("UNAUTHORIZED v2")
		return
	}

	// auth_message should be the current timestamp in seconds, check if its older than 10s
	timestamp, err := strconv.Atoi(auth_message)
	if err != nil || timestamp < (int(time.Now().Unix())-10) {
		ctx.SetStatusCode(fasthttp.StatusUnauthorized)
		ctx.SetBodyString("UNAUTHORIZED v3")
		return
	}

	// acme updates
	/*
		header: "change_action" can be: "SET" or "DEL"
		when "SET", header "domain" is the domain name, "token" is the token
		build a acme_http.HttpChallenge object and insert it into the db with acme_http.InsertHttpChallenge
	*/

	ctx.SetStatusCode(fasthttp.StatusOK)

	var change_action = string(ctx.Request.Header.Peek("change_action"))
	var domain = string(ctx.Request.Header.Peek("domain"))
	var public_token = string(ctx.Request.Header.Peek("public_token"))
	var full_token = string(ctx.Request.Header.Peek("full_token"))

	switch change_action {
	case "SET":
		// insert the challenge into db via acme_http.InsertHttpChallenge
		if domain == "" || public_token == "" || full_token == "" {
			ctx.SetStatusCode(fasthttp.StatusBadRequest)
			ctx.SetBodyString("BAD_REQUEST: domain, public_token or full_token missing")
			return
		}

		challenge := acme_http.HttpChallenge{
			Domain:      domain,
			PublicToken: public_token,
			FullToken:   full_token,
		}

		err := acme_http.InsertHttpChallenge(challenge, true)
		if err != nil {
			services.GetService("https").ErrorLog(err.Error())
			ctx.SetStatusCode(fasthttp.StatusInternalServerError)
			ctx.SetBodyString("INTERNAL_SERVER_ERROR")
			return
		}
	case "DEL":
		// delete the challenge from db via acme_http.DeleteHttpChallenge
		if public_token == "" {
			ctx.SetStatusCode(fasthttp.StatusBadRequest)
			ctx.SetBodyString("BAD_REQUEST: public_token missing")
			return
		}

		err := acme_http.DeleteHttpChallenge(public_token, true)
		if err != nil {
			services.GetService("https").ErrorLog(err.Error())
			ctx.SetStatusCode(fasthttp.StatusInternalServerError)
			ctx.SetBodyString("INTERNAL_SERVER_ERROR")
			return
		}
	default:
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		ctx.SetBodyString(fmt.Sprintf("BAD_REQUEST: %s", change_action))
		return
	}

	ctx.SetBodyString("OK")
}
