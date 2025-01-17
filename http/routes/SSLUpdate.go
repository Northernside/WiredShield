package routes

import (
	"fmt"
	"os"
	"wiredshield/modules/pgp"
	"wiredshield/utils/b64"

	"github.com/valyala/fasthttp"
)

// endpoint is supposed to be used by the master server to update the ssl certs of the clients
func SSLUpdate(ctx *fasthttp.RequestCtx) {
	if !ctx.IsGet() {
		ctx.SetStatusCode(fasthttp.StatusMethodNotAllowed)
		ctx.SetBodyString("METHOD_NOT_ALLOWED")
		return
	}

	// master auth logic
	var signature = string(ctx.Request.Header.Peek("signature"))
	var auth_message = string(ctx.Request.Header.Peek("auth_message"))
	if signature == "" {
		ctx.SetStatusCode(fasthttp.StatusUnauthorized)
		ctx.SetBodyString("UNAUTHORIZED")
		return
	}

	masterPub, err := pgp.LoadPublicKey(fmt.Sprintf("certs/%s-public.asc", "master"))
	if err != nil {
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		ctx.SetBodyString("INTERNAL_SERVER_ERROR")
		return
	}

	err = pgp.VerifySignature(auth_message, signature, masterPub)
	if err != nil {
		ctx.SetStatusCode(fasthttp.StatusUnauthorized)
		ctx.SetBodyString("UNAUTHORIZED")
		return
	}

	// ssl updates
	/*
		header: "change_action" can be: "SET" or "DEL"
		when "SET", header "domain" is the domain name, "cert" is the certificate, "key" is the private key
		copy the content from cert to certs/domain.crt and key to certs/domain.key
	*/

	ctx.SetStatusCode(fasthttp.StatusOK)

	var change_action = string(ctx.Request.Header.Peek("change_action"))
	var domain = string(ctx.Request.Header.Peek("domain"))

	switch change_action {
	case "SET":
		cert, err := b64.Decode(string(ctx.Request.Header.Peek("cert")))
		if err != nil {
			ctx.SetStatusCode(fasthttp.StatusInternalServerError)
			ctx.SetBodyString("INTERNAL_SERVER_ERROR")
			return
		}

		key, err := b64.Decode(string(ctx.Request.Header.Peek("key")))
		if err != nil {
			ctx.SetStatusCode(fasthttp.StatusInternalServerError)
			ctx.SetBodyString("INTERNAL_SERVER_ERROR")
			return
		}

		// write to disk
		certFile := fmt.Sprintf("certs/%s.crt", domain)
		keyFile := fmt.Sprintf("certs/%s.key", domain)

		certOut, err := os.Create(certFile)
		if err != nil {
			ctx.SetStatusCode(fasthttp.StatusInternalServerError)
			ctx.SetBodyString("INTERNAL_SERVER_ERROR")
			return
		}

		_, err = certOut.WriteString(cert)
		if err != nil {
			ctx.SetStatusCode(fasthttp.StatusInternalServerError)
			ctx.SetBodyString("INTERNAL_SERVER_ERROR")
			return
		}

		err = certOut.Close()
		if err != nil {
			ctx.SetStatusCode(fasthttp.StatusInternalServerError)
			ctx.SetBodyString("INTERNAL_SERVER_ERROR")
			return
		}

		keyOut, err := os.Create(keyFile)
		if err != nil {
			ctx.SetStatusCode(fasthttp.StatusInternalServerError)
			ctx.SetBodyString("INTERNAL_SERVER_ERROR")
			return
		}

		_, err = keyOut.WriteString(key)
		if err != nil {
			ctx.SetStatusCode(fasthttp.StatusInternalServerError)
			ctx.SetBodyString("INTERNAL_SERVER_ERROR")
			return
		}

		err = keyOut.Close()
		if err != nil {
			ctx.SetStatusCode(fasthttp.StatusInternalServerError)
			ctx.SetBodyString("INTERNAL_SERVER_ERROR")
			return
		}
	case "DEL":
		// delete the cert and key files
		certFile := fmt.Sprintf("certs/%s.crt", domain)
		keyFile := fmt.Sprintf("certs/%s.key", domain)

		err := os.Remove(certFile)
		if err != nil {
			ctx.SetStatusCode(fasthttp.StatusInternalServerError)
			ctx.SetBodyString("INTERNAL_SERVER_ERROR")
			return
		}

		err = os.Remove(keyFile)
		if err != nil {
			ctx.SetStatusCode(fasthttp.StatusInternalServerError)
			ctx.SetBodyString("INTERNAL_SERVER_ERROR")
			return
		}
	default:
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		ctx.SetBodyString("BAD_REQUEST")
		return
	}

	ctx.SetBodyString("OK")
}
