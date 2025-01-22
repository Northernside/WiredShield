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
		WAFService.InfoLog(fmt.Sprintf("Loaded Rules from %s: %+v\n", "rules/*.woof", Rules))
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
	defer func() {
		if r := recover(); r != nil {
			services.ProcessService.ErrorLog(fmt.Sprintf("Panic recovered in evaluateField: %v", r))
		}
	}()

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
			if val, ok := value.(string); ok {
				return evaluateFieldHelper(country, operation, val)
			}
		case "ip.geoip.asnum":
			services.ProcessService.InfoLog(fmt.Sprintf("ASN: %s, Value: %v, Type: %T", asn, value, value))
			if valList, ok := value.([]interface{}); ok {
				strAsn := fmt.Sprintf("%s", asn)
				return evaluateFieldHelper(strAsn, operation, valList)
			}
		}
	} else if strings.HasPrefix(field, "http.request.headers.") {
		headerKey := strings.TrimPrefix(field, "http.request.headers.")
		headerValue := ctx.Request.Header.Peek(headerKey)
		if val, ok := value.(string); ok {
			return evaluateFieldHelper(string(headerValue), operation, val)
		}
	} else {
		switch field {
		case "http.request.method":
			if val, ok := value.(string); ok {
				return evaluateFieldHelper(string(ctx.Method()), operation, val)
			}
		case "http.request.uri":
			if val, ok := value.(string); ok {
				return evaluateFieldHelper(string(ctx.RequestURI()), operation, val)
			}
		}
	}

	return false
}

func evaluateFieldHelper(fieldValue string, operation string, value interface{}) bool {
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
				var valStr string
				switch v := v.(type) {
				case string:
					valStr = v
				case float64:
					valStr = fmt.Sprintf("%.0f", v)
				default:
					continue
				}

				if strings.EqualFold(fieldValue, valStr) {
					return true
				}
			}
		}
	case "not_in":
		if valList, ok := value.([]interface{}); ok {
			for _, v := range valList {
				var valStr string
				switch v := v.(type) {
				case string:
					valStr = v
				case float64:
					valStr = fmt.Sprintf("%.0f", v)
				default:
					continue
				}

				if strings.EqualFold(fieldValue, valStr) {
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
		services.ProcessService.InfoLog(fmt.Sprintf("###0 %s %v %s", rule.Group, rule.Rules, rule.Action))
		return evaluateGroup(rule.Rules, rule.Group, ctx)
	}

	services.ProcessService.InfoLog(fmt.Sprintf("###X1 Field: %s, Operation: %s, Value: %v, Type: %T", rule.Field, rule.Operation, rule.Value, rule.Value))

	// Check type of rule.Value explicitly
	if valInt, ok := rule.Value.(int); ok {
		rule.Value = strconv.Itoa(valInt)
		services.ProcessService.InfoLog(fmt.Sprintf("Converted int Value: %s", rule.Value))
	}

	if valFloat, ok := rule.Value.(float64); ok {
		rule.Value = fmt.Sprintf("%.0f", valFloat)
		services.ProcessService.InfoLog(fmt.Sprintf("Converted float64 Value to string: %s", rule.Value))
	}

	if valList, ok := rule.Value.([]interface{}); ok {
		services.ProcessService.InfoLog(fmt.Sprintf("Value is a list: %v", valList))
	}

	services.ProcessService.InfoLog(fmt.Sprintf("###X3 Processed Value Type: %T", rule.Value))

	// Avoid crash by checking before casting
	if valStr, ok := rule.Value.(string); ok {
		return evaluateField(rule.Field, rule.Operation, valStr, ctx)
	}

	services.ProcessService.InfoLog("Value is not a string")
	return false
}
