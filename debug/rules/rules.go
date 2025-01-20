package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"wiredshield/modules/whois"
	errorpages "wiredshield/pages/error"
	"wiredshield/services"

	"github.com/valyala/fasthttp"
)

var (
	WAFService  *services.Service
	blockedPage string
)

type Rule struct {
	Field     string `json:"field,omitempty"`
	Operation string `json:"operation"`
	Value     string `json:"value"`
	Group     string `json:"group,omitempty"`
	Rules     []Rule `json:"rules,omitempty"`
	Action    string `json:"action"`
}

var (
	Rules = []Rule{}
)

func main() {
	_page := errorpages.ErrorPage{Code: 403, Message: errorpages.Error403}
	blockedPage = _page.ToHTML()

	// load every *.woof file in rules/
	files, err := filepath.Glob("rules/*.woof")
	if err != nil {
		panic(err)
	}

	for _, file := range files {
		fileContent, err := os.ReadFile(file)
		if err != nil {
			panic(err)
		}

		var rules []Rule
		if err := json.Unmarshal(fileContent, &rules); err != nil {
			fmt.Println("Error parsing rules:", err)
			return
		}

		Rules = append(Rules, rules...)
	}

	ctx := &fasthttp.RequestCtx{}
	ctx.Request.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3")
	ctx.Request.Header.SetMethod("POST")
	if EvaluateRule(ctx) {
		fmt.Println("Matched rule")
	} else {
		fmt.Println("Does not match any rule")
	}
}

func EvaluateRule(ctx *fasthttp.RequestCtx) bool {
	for _, rule := range Rules {
		if evaluateRule(ctx, rule) {
			fmt.Println("Matched rule:", rule)
			return true
		}
	}

	return false
}

func getGeoIP(ip string) (string, string, error) {
	country, _ := whois.GetCountry(ip)
	asn, _ := whois.GetASN(ip)
	return country, fmt.Sprintf("%d", asn), nil
}

func evaluateField(field string, operation string, value string, ctx *fasthttp.RequestCtx) bool {
	if strings.HasPrefix(field, "ip.geoip") {
		ip := string(ctx.RemoteIP())
		// check if ip is valid, if not, use "1.1.1.1"
		if net.ParseIP(ip) == nil {
			ip = "1.1.1.1"
		}

		country, asn, err := getGeoIP(ip)
		if err != nil {
			return false
		}

		switch {
		case field == "ip.geoip.country":
			return evaluateFieldHelper(country, operation, value)
		case field == "ip.geoip.asnum":
			return evaluateFieldHelper(asn, operation, value)
		default:
			return false
		}
	} else {
		switch field {
		case "http.request.method":
			return evaluateFieldHelper(string(ctx.Method()), operation, value)
		case "http.request.uri":
			return evaluateFieldHelper(string(ctx.RequestURI()), operation, value)
		case "http.request.host":
			return evaluateFieldHelper(string(ctx.Host()), operation, value)
		case "http.request.path":
			return evaluateFieldHelper(string(ctx.Path()), operation, value)
		case "http.request.query":
			return evaluateFieldHelper(string(ctx.QueryArgs().QueryString()), operation, value)
		case "http.request.body":
			body := string(ctx.PostBody())
			return evaluateFieldHelper(body, operation, value)
		case "http.request.header":
			headerValue := string(ctx.Request.Header.Peek(value))
			return evaluateFieldHelper(headerValue, operation, value)
		case "http.user_agent":
			userAgent := string(ctx.UserAgent())
			return evaluateFieldHelper(userAgent, operation, value)
		case "http.request.version":
			version := string(ctx.Request.Header.Peek("Version"))
			return evaluateFieldHelper(version, operation, value)
		default:
			return false
		}
	}
}

func evaluateFieldHelper(fieldValue, operation, value string) bool {
	switch operation {
	case "equal":
		return strings.EqualFold(fieldValue, value)
	case "not_equal":
		return !strings.EqualFold(fieldValue, value)
	case "contains":
		return strings.Contains(fieldValue, value)
	default:
		return false
	}
}

func evaluateGroup(rules []Rule, group string, ctx *fasthttp.RequestCtx) bool {
	result := false
	for _, rule := range rules {
		if len(rule.Rules) > 0 {
			result = evaluateGroup(rule.Rules, rule.Group, ctx)
		} else {
			result = evaluateField(rule.Field, rule.Operation, rule.Value, ctx)
		}

		if group == "AND" && !result {
			return false
		}

		if group == "OR" && result {
			return true
		}
	}

	return result
}

func evaluateRule(ctx *fasthttp.RequestCtx, rule Rule) bool {
	if len(rule.Rules) > 0 {
		return evaluateGroup(rule.Rules, rule.Group, ctx)
	}

	return evaluateField(rule.Field, rule.Operation, rule.Value, ctx)
}
