package routes

import (
	"strconv"
	"wiredshield/modules/db"
	"wiredshield/modules/epoch"

	"github.com/valyala/fasthttp"
)

func AddRecord(ctx *fasthttp.RequestCtx) {
	/*
		A: ["Name", "Address", "TTL", "Protected"],
		AAAA: ["Name", "Address", "TTL", "Protected"],
		CNAME: ["Name", "Target", "TTL"],
		TXT: ["Name", "Value", "TTL"],
		MX: ["Name", "Priority", "Target", "TTL"],
		NS: ["Name", "Nameserver", "TTL"],
		SOA: ["Nameserver", "Email", "Serial", "Refresh", "Retry", "Expire", "TTL"],
		CAA: ["Name", "Flag", "Tag", "Value", "TTL"],
		SRV: ["Name", "Priority", "Weight", "Port", "Target", "TTL"]

		?domain=<domain>
		headers:
			wired-name, wired-address, wired-ttl, wired-protected, wired-value, wired-priority,
			wired-nameserver, wired-email, wired-serial, wired-refresh, wired-retry, wired-expire,
			wired-flag, wired-tag, wired-target, wired-weight, wired-port
	*/

	var domain = string(ctx.Request.Header.Peek("wired-name"))
	var ip = string(ctx.Request.Header.Peek("wired-address"))
	var ttl, _ = strconv.Atoi(string(ctx.Request.Header.Peek("wired-ttl")))
	var protected = string(ctx.Request.Header.Peek("wired-protected"))
	var value = string(ctx.Request.Header.Peek("wired-value"))
	var priority, _ = strconv.Atoi(string(ctx.Request.Header.Peek("wired-priority")))
	var nameserver = string(ctx.Request.Header.Peek("wired-nameserver"))
	var email = string(ctx.Request.Header.Peek("wired-email"))
	var serial, _ = strconv.Atoi(string(ctx.Request.Header.Peek("wired-serial")))
	var refresh, _ = strconv.Atoi(string(ctx.Request.Header.Peek("wired-refresh")))
	var retry, _ = strconv.Atoi(string(ctx.Request.Header.Peek("wired-retry")))
	var expire, _ = strconv.Atoi(string(ctx.Request.Header.Peek("wired-expire")))
	var flag, _ = strconv.Atoi(string(ctx.Request.Header.Peek("wired-flag")))
	var tag = string(ctx.Request.Header.Peek("wired-tag"))
	var target = string(ctx.Request.Header.Peek("wired-target"))
	var weight, _ = strconv.Atoi(string(ctx.Request.Header.Peek("wired-weight")))
	var port, _ = strconv.Atoi(string(ctx.Request.Header.Peek("wired-port")))

	var id uint64
	snowflake, err := epoch.NewSnowflake(512)
	if err != nil {
		ctx.Error("Failed to generate ID", fasthttp.StatusInternalServerError)
		return
	}

	id = snowflake.GenerateID()

	switch string(ctx.Request.Header.Peek("wired-type")) {
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
		record.Text = value

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
		record.NS = nameserver

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
		record.PrimaryNS = nameserver
		record.AdminEmail = email
		record.Serial = uint32(serial)
		record.Refresh = uint32(refresh)
		record.Retry = uint32(retry)
		record.Expire = uint32(expire)
		record.MinimumTTL = uint32(ttl)

		db.InsertRecord(record, true)
	}

	ctx.SetStatusCode(fasthttp.StatusOK)
	ctx.SetBodyString("Record added successfully")
}
