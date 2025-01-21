package rules

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
	"wiredshield/modules/whois"
	"wiredshield/services"

	"github.com/valyala/fasthttp"
)

var (
	WAFService *services.Service
)

type Rule struct {
	Field     string      `json:"field,omitempty"`
	Operation string      `json:"operation"`
	Value     interface{} `json:"value"`
	Group     string      `json:"group,omitempty"`
	Rules     []Rule      `json:"rules,omitempty"`
	Action    string      `json:"action"`
}

var (
	Rules = []Rule{}
)

func init() {
	WAFService := services.RegisterService("waf", "Web Application Firewall")
	WAFService.Boot = func() {
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

			type RuleFile struct {
				Rules []Rule `json:"rules"`
			}

			var rules []Rule
			if json.Unmarshal(fileContent, &rules) == nil {
				Rules = append(Rules, rules...)
			} else {
				var ruleFile RuleFile
				if err := json.Unmarshal(fileContent, &ruleFile); err != nil {
					fmt.Printf("Error parsing %s: %s\n", file, err)
					continue
				}

				Rules = append(Rules, ruleFile.Rules...)
			}
		}

		WAFService.OnlineSince = time.Now().Unix()
		WAFService.InfoLog(fmt.Sprintf("Loaded %d rules", len(Rules)))
	}
}

func EvaluateRule(ctx *fasthttp.RequestCtx) bool {
	for _, rule := range Rules {
		if evaluateRule(ctx, rule) {
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
		ip := ctx.RemoteIP().String()
		// check if ip is valid, if not, use "1.1.1.1"
		if net.ParseIP(ip) == nil {
			ip = "1.1.1.1"
		}

		country, asn, err := getGeoIP(ip)
		if err != nil {
			return false
		}

		switch field {
		case "ip.geoip.country":
			return evaluateFieldHelper(country, operation, value)
		case "ip.geoip.asnum":
			return evaluateFieldHelper(asn, operation, value)
		default:
			return false
		} // header check
	} else if strings.HasPrefix(field, "http.request.headers.") {
		headerKey := strings.TrimPrefix(field, "http.request.headers.")
		headerValue := ctx.Request.Header.Peek(headerKey)
		return evaluateFieldHelper(string(headerValue), operation, value)
	} else { // meta checks
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
			return evaluateFieldHelper(string(ctx.PostBody()), operation, value)
		case "http.user_agent":
			return evaluateFieldHelper(string(ctx.UserAgent()), operation, value)
		case "http.request.version":
			version := string(ctx.Request.Header.Peek("Version"))
			return evaluateFieldHelper(version, operation, value)
		default:
			return false
		}
	}
}

func evaluateFieldHelper(fieldValue, operation string, value interface{}) bool {
	switch operation {
	case "equal":
		if val, ok := value.(string); ok {
			return strings.EqualFold(strings.ToLower(fieldValue), strings.ToLower(val))
		}
	case "not_equal":
		if val, ok := value.(string); ok {
			return !strings.EqualFold(strings.ToLower(fieldValue), strings.ToLower(val))
		}
	case "contains":
		if val, ok := value.(string); ok {
			return strings.Contains(strings.ToLower(fieldValue), strings.ToLower(val))
		}
	case "in":
		if valList, ok := value.([]interface{}); ok {
			for _, v := range valList {
				if val, ok := v.(string); ok && strings.EqualFold(fieldValue, val) {
					return true
				}
			}
		}
	case "not_in":
		if valList, ok := value.([]interface{}); ok {
			for _, v := range valList {
				if val, ok := v.(string); ok && strings.EqualFold(fieldValue, val) {
					return false
				}
			}

			return true
		}
	}

	return false
}

func evaluateGroup(rules []Rule, group string, ctx *fasthttp.RequestCtx) bool {
	result := false
	for _, rule := range rules {
		if len(rule.Rules) > 0 {
			result = evaluateGroup(rule.Rules, rule.Group, ctx)
		} else {
			result = evaluateField(rule.Field, rule.Operation, rule.Value.(string), ctx)
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

	return evaluateField(rule.Field, rule.Operation, rule.Value.(string), ctx)
}
