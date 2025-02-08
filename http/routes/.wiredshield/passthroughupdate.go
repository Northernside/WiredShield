package routes

import (
	"fmt"
	"strconv"
	"time"
	"wiredshield/modules/db/passthrough"
	"wiredshield/modules/env"
	"wiredshield/modules/pgp"
	"wiredshield/services"
	"wiredshield/utils/b64"

	"github.com/valyala/fasthttp"
)

// endpoint is supposed to be used by the master server to update the passthrough details of the clients
func PassthroughUpdate(ctx *fasthttp.RequestCtx) {
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
	var id, _ = strconv.Atoi(string(ctx.Request.Header.Peek("id")))
	var domain = string(ctx.Request.Header.Peek("domain"))
	var path = string(ctx.Request.Header.Peek("path"))
	var target_addr = string(ctx.Request.Header.Peek("target_addr"))
	var target_port, _ = strconv.Atoi(string(ctx.Request.Header.Peek("target_port")))
	var target_path = string(ctx.Request.Header.Peek("target_path"))
	var ssl = bool(string(ctx.Request.Header.Peek("ssl")) == "true")

	switch change_action {
	case "SET":
		// insert the challenge into db via passthrough.InsertPassthrough
		if id == 0 || domain == "" || path == "" || target_addr == "" || target_port == 0 || target_path == "" {
			ctx.SetStatusCode(fasthttp.StatusBadRequest)
			ctx.SetBodyString("BAD_REQUEST: id, domain, path, target_addr, target_port or target_path missing")
			return
		}

		pt := passthrough.Passthrough{
			Id:         uint64(id),
			Domain:     domain,
			Path:       path,
			TargetAddr: target_addr,
			TargetPort: uint16(target_port),
			TargetPath: target_path,
			Ssl:        ssl,
		}

		err := passthrough.InsertPassthrough(pt, uint64(id), true)
		if err != nil {
			services.GetService("https").ErrorLog(err.Error())
			ctx.SetStatusCode(fasthttp.StatusInternalServerError)
			ctx.SetBodyString("INTERNAL_SERVER_ERROR")
			return
		}
	case "DEL":
		// delete the challenge from db via passthrough.DeletePassthrough
		if id == 0 {
			ctx.SetStatusCode(fasthttp.StatusBadRequest)
			ctx.SetBodyString("BAD_REQUEST: id missing")
			return
		}

		err := passthrough.DeletePassthrough(uint64(id), true)
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
