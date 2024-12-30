package routes

import (
	"fmt"
	"wiredshield/modules/db"
	"wiredshield/modules/pgp"

	"github.com/valyala/fasthttp"
)

// endpoint is supposed to be used by the master server to update the DNS records of the clients
func DNSUpdate(ctx *fasthttp.RequestCtx) {
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

	// dns updates
	/*
		header: "change_action" can be: "SET" or "DEL"
		header: "change_record_type" can be A, AAAA, CAA, NS, MX, SRV, SOA, TXT, CNAME
	*/

	ctx.SetStatusCode(fasthttp.StatusOK)

	var change_action = string(ctx.Request.Header.Peek("change_action"))
	var change_record_type = string(ctx.Request.Header.Peek("change_record_type"))

	var compatible_types = []string{"A", "AAAA", "CAA", "NS", "MX", "SRV", "SOA", "TXT", "CNAME"}
	if !contains(compatible_types, change_record_type) {
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		ctx.SetBodyString("BAD_REQUEST")
		return
	}

	switch change_action {
	case "SET":
		var domain = string(ctx.Request.Header.Peek("dns_domain"))
		var ip = string(ctx.Request.Header.Peek("dns_ip"))
		var protected = string(ctx.Request.Header.Peek("protected"))
		var text = string(ctx.Request.Header.Peek("text"))

		// set the record
		switch change_record_type {
		case "A":
			var record db.ARecord
			record.Domain = domain
			record.IP = ip
			record.Protected = protected == "true"

			db.UpdateRecord(change_record_type, domain, record)
		case "AAAA":
			var record db.AAAARecord
			record.Domain = domain
			record.IP = ip
			record.Protected = protected == "true"

			db.UpdateRecord(change_record_type, domain, record)
		case "TXT":
			var record db.TXTRecord
			record.Domain = domain
			record.Text = text

			db.UpdateRecord(change_record_type, domain, record)
		}
	case "DEL":
		// delete the record
	default:
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		ctx.SetBodyString("BAD_REQUEST")
		return
	}

	ctx.SetBodyString("OK")
}

func contains(arr []string, str string) bool {
	for _, a := range arr {
		if a == str {
			return true
		}
	}

	return false
}
