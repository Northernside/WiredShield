package routes

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	wireddns "wiredshield/dns"
	"wiredshield/modules/db"
	"wiredshield/modules/env"
	"wiredshield/modules/pgp"
	"wiredshield/modules/whois"
	"wiredshield/services"

	"github.com/valyala/fasthttp"
)

var (
	pendingAuthentications = make(map[string]string)
)

func ProxyAuth(ctx *fasthttp.RequestCtx) {
	if !ctx.IsGet() {
		ctx.SetStatusCode(fasthttp.StatusMethodNotAllowed)
		ctx.SetBodyString("METHOD_NOT_ALLOWED")
		return
	}

	master := env.GetEnv("MASTER", "false")
	if master == "false" {
		ctx.SetStatusCode(fasthttp.StatusForbidden)
		ctx.SetBodyString("NOT_A_MASTER")
		return
	}

	state := string(ctx.Request.Header.Peek("state"))
	switch state {
	case "1":
		clientName := string(ctx.Request.Header.Peek("ws-client-name"))
		if clientName == "" {
			ctx.SetStatusCode(fasthttp.StatusBadRequest)
			ctx.SetBodyString("BAD_REQUEST")
			return
		}

		client, err := db.GetClient(clientName)
		if err != nil {
			ctx.SetStatusCode(fasthttp.StatusNotFound)
			ctx.SetBodyString("NOT_FOUND")
			return
		}

		services.ClientMap[clientName] = client
		ctx.SetStatusCode(fasthttp.StatusOK)

		signingCode := randomString() + "." + clientName
		ctx.Response.Header.Set("state", "2")
		ctx.Response.Header.Set("ws-signing-code", signingCode)

		pendingAuthentications[clientName] = signingCode
		return
	case "2":
		clientName := string(ctx.Request.Header.Peek("ws-client-name"))
		if clientName == "" {
			ctx.SetStatusCode(fasthttp.StatusBadRequest)
			ctx.SetBodyString("BAD_REQUEST")
			return
		}

		if pendingAuthentications[clientName] == "" {
			ctx.SetStatusCode(fasthttp.StatusUnauthorized)
			ctx.SetBodyString("UNAUTHORIZED")
			return
		}

		signingCode := string(ctx.Request.Header.Peek("ws-signing-code"))
		if signingCode == "" {
			ctx.SetStatusCode(fasthttp.StatusBadRequest)
			ctx.SetBodyString("BAD_REQUEST")
			return
		}

		if signingCode != pendingAuthentications[clientName] {
			ctx.SetStatusCode(fasthttp.StatusUnauthorized)
			ctx.SetBodyString("UNAUTHORIZED")
			return
		}

		signingCodeSignature := string(ctx.Request.Header.Peek("ws-signing-code-signature"))
		if signingCodeSignature == "" {
			ctx.SetStatusCode(fasthttp.StatusBadRequest)
			ctx.SetBodyString("BAD_REQUEST")
			return
		}

		// turn the b64 signature into a string
		signature, err := base64.StdEncoding.DecodeString(signingCodeSignature)
		if err != nil {
			ctx.SetStatusCode(fasthttp.StatusBadRequest)
			ctx.SetBodyString("BAD_REQUEST")
			return
		}

		publicKey, err := pgp.LoadPublicKey(fmt.Sprintf("certs/%s-public.asc", clientName))
		if err != nil {
			ctx.SetStatusCode(fasthttp.StatusInternalServerError)
			ctx.SetBodyString("INTERNAL_SERVER_ERROR")
			return
		}

		err = pgp.VerifySignature(signingCode, string(signature), publicKey)
		if err != nil {
			ctx.SetStatusCode(fasthttp.StatusUnauthorized)
			ctx.SetBodyString("UNAUTHORIZED")
			return
		}

		delete(pendingAuthentications, clientName)

		token, err := pgp.GenerateToken(services.ServerPrivateKey, clientName)
		if err != nil {
			ctx.SetStatusCode(fasthttp.StatusInternalServerError)
			ctx.SetBodyString("INTERNAL_SERVER_ERROR")
			return
		}

		client := services.ClientMap[clientName]
		client.Ready = true

		services.ClientMap[clientName] = client

		country, err := whois.GetCountry(client.IPAddress)
		if err != nil {
			services.ProcessService.ErrorLog(fmt.Sprintf("failed to get country for %s: %v", client.IPAddress, err))

			ctx.SetStatusCode(fasthttp.StatusInternalServerError)
			ctx.SetBodyString("INTERNAL_SERVER_ERROR")
			return
		}

		if _, ok := wireddns.ResolversV4[country]; !ok {
			wireddns.ResolversV4[country] = []net.IP{net.ParseIP(client.IPAddress)}
		} else {
			wireddns.ResolversV4[country] = append(wireddns.ResolversV4[country], net.ParseIP(client.IPAddress))
		}

		ctx.Response.Header.Set("ws-access-token", token)
		ctx.Response.Header.Set("state", "3")
		ctx.SetStatusCode(fasthttp.StatusOK)
		return
	}
}

func randomString() string {
	b := make([]byte, 4)
	_, err := rand.Read(b)
	if err != nil {
		panic(err)
	}

	return hex.EncodeToString(b)
}
