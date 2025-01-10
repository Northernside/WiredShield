package routes

import (
	"encoding/base64"
	"fmt"
	"strconv"
	"time"
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

	/*
		logic:
			- verify the signature (compare headers: signature and auth_message)
	*/

	// master auth logic
	var signature = string(ctx.Request.Header.Peek("signature"))
	var auth_message = string(ctx.Request.Header.Peek("auth_message"))
	if signature == "" || auth_message == "" {
		ctx.SetStatusCode(fasthttp.StatusUnauthorized)
		ctx.SetBodyString("UNAUTHORIZED v1")
		return
	}

	woofPub, err := pgp.LoadPublicKey("certs/woof-public.asc")
	if err != nil {
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		ctx.SetBodyString("INTERNAL_SERVER_ERROR")
		return
	}

	b64Sig, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		ctx.SetBodyString("BAD_REQUEST")
		return
	}

	b64SigStr := string(b64Sig)
	err = pgp.VerifySignature(auth_message, b64SigStr, woofPub)
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

	// dns updates
	/*
		header: "change_action" can be: "SET" or "DEL"
		header: "change_record_type" can be A, AAAA, CAA, NS, MX, SRV, SOA, TXT, CNAME
	*/

	ctx.SetStatusCode(fasthttp.StatusOK)

	var change_action = string(ctx.Request.Header.Peek("change_action"))
	var change_record_type = string(ctx.Request.Header.Peek("change_record_type"))

	var compatible_types = []string{"A", "AAAA", "CAA", "NS", "MX", "SRV", "SOA", "TXT", "CNAME"}
	if !contains(compatible_types, change_record_type) && change_action == "SET" {
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		ctx.SetBodyString(fmt.Sprintf("BAD_REQUEST: %s", change_record_type))
		return
	}

	var id, _ = strconv.Atoi(string(ctx.Request.Header.Peek("id")))
	var domain = string(ctx.Request.Header.Peek("dns_domain"))
	var ip = string(ctx.Request.Header.Peek("dns_ip"))
	var protected = string(ctx.Request.Header.Peek("protected"))
	var text = string(ctx.Request.Header.Peek("text"))
	var target = string(ctx.Request.Header.Peek("target"))
	var priority, _ = strconv.Atoi(string(ctx.Request.Header.Peek("priority")))
	var weight, _ = strconv.Atoi(string(ctx.Request.Header.Peek("weight")))
	var port, _ = strconv.Atoi(string(ctx.Request.Header.Peek("port")))
	var flag, _ = strconv.Atoi(string(ctx.Request.Header.Peek("flag")))
	var tag = string(ctx.Request.Header.Peek("tag"))
	var value = string(ctx.Request.Header.Peek("value"))
	var ns = string(ctx.Request.Header.Peek("ns"))
	var primary_ns = string(ctx.Request.Header.Peek("primary_ns"))
	var admin_email = string(ctx.Request.Header.Peek("admin_email"))
	var serial, _ = strconv.Atoi(string(ctx.Request.Header.Peek("serial")))
	var refresh, _ = strconv.Atoi(string(ctx.Request.Header.Peek("refresh")))
	var retry, _ = strconv.Atoi(string(ctx.Request.Header.Peek("retry")))
	var expire, _ = strconv.Atoi(string(ctx.Request.Header.Peek("expire")))
	var minimum_ttl, _ = strconv.Atoi(string(ctx.Request.Header.Peek("minimum_ttl")))
	switch change_action {
	case "SET":
		// set the record
		switch change_record_type {
		case "A":
			var record db.ARecord
			record.ID = uint64(id)
			record.Domain = domain
			record.IP = ip
			record.Protected = protected == "true"

			db.InsertRecord(record, true)
		case "AAAA":
			var record db.AAAARecord
			record.ID = uint64(id)
			record.Domain = domain
			record.IP = ip
			record.Protected = protected == "true"

			db.InsertRecord(record, true)
		case "TXT":
			var record db.TXTRecord
			record.ID = uint64(id)
			record.Domain = domain
			record.Text = text

			db.InsertRecord(record, true)
		case "CNAME":
			var record db.CNAMERecord
			record.ID = uint64(id)
			record.Domain = domain
			record.Target = target

			db.InsertRecord(record, true)
		case "CAA":
			var record db.CAARecord
			record.ID = uint64(id)
			record.Domain = domain
			record.Flag = flag
			record.Tag = tag
			record.Value = value

			db.InsertRecord(record, true)
		case "NS":
			var record db.NSRecord
			record.ID = uint64(id)
			record.Domain = domain
			record.NS = ns

			db.InsertRecord(record, true)
		case "MX":
			var record db.MXRecord
			record.ID = uint64(id)
			record.Domain = domain
			record.Priority = uint16(priority)
			record.Target = target

			db.InsertRecord(record, true)
		case "SRV":
			var record db.SRVRecord
			record.ID = uint64(id)
			record.Domain = domain
			record.Priority = priority
			record.Weight = weight
			record.Port = port
			record.Target = target

			db.InsertRecord(record, true)
		case "SOA":
			var record db.SOARecord
			record.ID = uint64(id)
			record.Domain = domain
			record.PrimaryNS = primary_ns
			record.AdminEmail = admin_email
			record.Serial = uint32(serial)
			record.Refresh = uint32(refresh)
			record.Retry = uint32(retry)
			record.Expire = uint32(expire)
			record.MinimumTTL = uint32(minimum_ttl)

			db.InsertRecord(record, true)
		}
	case "DEL":
		var id, _ = strconv.Atoi(string(ctx.Request.Header.Peek("id")))
		var domain = string(ctx.Request.Header.Peek("dns_domain"))

		// delete the record
		db.DeleteRecord(uint64(id), domain, true)
	default:
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		ctx.SetBodyString(fmt.Sprintf("BAD_REQUEST: %s", change_action))
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
