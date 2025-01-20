package routes

import (
	"strconv"
	"strings"
	"wiredshield/modules/db"
	"wiredshield/services"

	"github.com/valyala/fasthttp"
)

func DeleteRecord(ctx *fasthttp.RequestCtx) {
	// https://dash.as214428.net/.wiredshield/api/domains/records/6090066143215616?domain=northernsi.de

	// grab id by path and domain by query
	var domain = string(ctx.QueryArgs().Peek("domain"))
	// split by last /, grab everything after that and then omit the query
	var id = string(ctx.Path())[strings.LastIndex(string(ctx.Path()), "/")+1 : strings.Index(string(ctx.Path()), "?")]

	services.ProcessService.InfoLog("Deleting record with ID " + id + " from domain " + domain)

	_id, _ := strconv.Atoi(id)
	db.DeleteRecord(uint64(_id), domain, false)
}
