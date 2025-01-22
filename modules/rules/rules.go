package rules

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
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

func evaluateField(field string, operation string, value interface{}, ctx *fasthttp.RequestCtx) bool {
	// convert value to string if it's an int
	services.ProcessService.InfoLog(fmt.Sprintf("#-2 %s %s %s", field, operation, value))
	if valInt, ok := value.(int); ok {
		services.ProcessService.InfoLog(fmt.Sprintf("#-1 %s %s %s", field, operation, value))
		value = strconv.Itoa(valInt)
	}

	services.ProcessService.InfoLog(fmt.Sprintf("#0 %s %s %s", field, operation, value))

	services.ProcessService.InfoLog(fmt.Sprintf("#1 %s %s %s", field, operation, value))
	if strings.HasPrefix(field, "ip.geoip") {
		ip := ctx.RemoteIP().String()
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
			services.ProcessService.InfoLog(fmt.Sprintf("#2 %s %s %s", asn, operation, value))
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
	services.ProcessService.InfoLog(fmt.Sprintf("#3 %s %s %s", fieldValue, operation, value))
	// replace any int with string, even if value is an array, then iterate over it
	if valList, ok := value.([]interface{}); ok {
		services.ProcessService.InfoLog(fmt.Sprintf("#4 %s %s %s", fieldValue, operation, value))
		for i, v := range valList {
			services.ProcessService.InfoLog(fmt.Sprintf("#5 %s %s %s", fieldValue, operation, value))
			if valInt, ok := v.(int); ok {
				services.ProcessService.InfoLog(fmt.Sprintf("#6 %s %s %s", fieldValue, operation, value))
				valList[i] = strconv.Itoa(valInt)
				services.ProcessService.InfoLog(fmt.Sprintf("#7 %s %s %s", fieldValue, operation, value))
			}
		}
	} else if valInt, ok := value.(int); ok {
		services.ProcessService.InfoLog(fmt.Sprintf("#8 %s %s %s", fieldValue, operation, value))
		value = strconv.Itoa(valInt)
	}

	services.ProcessService.InfoLog(fmt.Sprintf("#9 %s %s %s", fieldValue, operation, value))

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
		services.ProcessService.InfoLog(fmt.Sprintf("#10 %s %s %s", fieldValue, operation, value))
		if valList, ok := value.([]interface{}); ok {
			services.ProcessService.InfoLog(fmt.Sprintf("#11 %s %s %s", fieldValue, operation, value))
			for _, v := range valList {
				services.ProcessService.InfoLog(fmt.Sprintf("#12 %s %s %s", fieldValue, operation, value))
				if valStr, ok := v.(string); ok && strings.EqualFold(fieldValue, valStr) {
					services.ProcessService.InfoLog(fmt.Sprintf("#13 %s %s %s", fieldValue, operation, value))
					return true
				}
			}

			services.ProcessService.InfoLog(fmt.Sprintf("#14 %s %s %s", fieldValue, operation, value))

			return false
		}
	case "not_in":
		if valList, ok := value.([]interface{}); ok {
			for _, v := range valList {
				if valStr, ok := v.(string); ok && strings.EqualFold(fieldValue, valStr) {
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
		services.ProcessService.InfoLog(fmt.Sprintf("###1 %s %s %s", rule.Group, rule.Rules, rule.Action))
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
		services.ProcessService.InfoLog(fmt.Sprintf("###0 %s %s %s", rule.Group, rule.Rules, rule.Action))
		return evaluateGroup(rule.Rules, rule.Group, ctx)
	}

	services.ProcessService.InfoLog(fmt.Sprintf("###X1 %s %s %s", rule.Field, rule.Operation, rule.Value))
	// convert rule.Value to string first if its an int
	if valInt, ok := rule.Value.(int); ok {
		services.ProcessService.InfoLog(fmt.Sprintf("###X2 %s %s %s", rule.Field, rule.Operation, rule.Value))
		rule.Value = strconv.Itoa(valInt)
	}

	// log type
	services.ProcessService.InfoLog(fmt.Sprintf("###X3 type: %T", rule.Value))

	return evaluateField(rule.Field, rule.Operation, rule.Value.(string), ctx)
}
