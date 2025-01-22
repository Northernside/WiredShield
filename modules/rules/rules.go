package rules

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/valyala/fasthttp"
)

var rules []Rule

type Rule struct {
	Group string    `json:"group"`
	Rules []SubRule `json:"rules"`
}

type SubRule struct {
	Field     string   `json:"field"`
	Operation string   `json:"operation"`
	Value     []string `json:"value"`
}

func init() {
	var err error
	rules, err = loadRules("rules/*.woof")
	if err != nil {
		panic(err)
	}
}

func MatchRules(ctx *fasthttp.RequestCtx) bool {
	for _, rule := range rules {
		ruleMatched := false
		for _, subRule := range rule.Rules {
			matches := evaluateField(subRule.Field, subRule.Operation, subRule.Value, ctx)
			if (rule.Group == "OR" && matches) || (rule.Group == "AND" && !matches) {
				ruleMatched = true
				break
			}
		}

		if ruleMatched {
			return true
		}
	}

	return false
}

func evaluateField(field, operation string, value []string, ctx *fasthttp.RequestCtx) bool {
	var fieldValue string

	switch field {
	case "http.request.method":
		fieldValue = string(ctx.Method())
	case "http.request.uri":
		fieldValue = string(ctx.Request.URI().String())
	case "http.request.host":
		fieldValue = string(ctx.Request.Host())
	case "http.request.path":
		fieldValue = string(ctx.Request.URI().Path())
	case "http.request.query":
		fieldValue = string(ctx.Request.URI().QueryString())
	case "http.request.body":
		fieldValue = string(ctx.Request.Body())
	case "http.user_agent":
		fieldValue = string(ctx.UserAgent())
	case "http.request.version":
		fieldValue = string(ctx.Request.Header.Protocol())
	case "ip.geoip.country":
		fieldValue = "DE"
	case "ip.geoip.asnum":
		fieldValue = "3320"
	default:
		fieldValue = string(ctx.Request.Header.Peek(field[len("http.request.headers."):]))
	}

	switch operation {
	case "equal":
		return fieldValue == value[0]
	case "not_equal":
		return fieldValue != value[0]
	case "contains":
		return strings.Contains(fieldValue, value[0])
	case "not_contains":
		return !strings.Contains(fieldValue, value[0])
	case "in":
		for _, v := range value {
			if fieldValue == v {
				return true
			}
		}

		return false
	case "not_in":
		for _, v := range value {
			if fieldValue == v {
				return false
			}
		}

		return true
	default:
		return false
	}
}

func loadRules(pattern string) ([]Rule, error) {
	files, err := filepath.Glob(pattern)
	if err != nil {
		return nil, err
	}

	var allRules []Rule
	for _, file := range files {
		rules, err := loadRulesFromFile(file)
		if err != nil {
			return nil, err
		}

		allRules = append(allRules, rules...)
	}

	return allRules, nil
}

func loadRulesFromFile(filename string) ([]Rule, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var rules []Rule
	decoder := json.NewDecoder(file)
	err = decoder.Decode(&rules)
	if err != nil {
		return nil, err
	}

	return rules, nil
}
