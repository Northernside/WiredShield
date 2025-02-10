package rules

import (
	"encoding/json"
	"fmt"
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

	rules []Rule
)

type Rule struct {
	Group  string    `json:"group"`
	Action string    `json:"action"`
	Rules  []SubRule `json:"rules"`
}

type SubRule struct {
	Field     string   `json:"field"`
	Operation string   `json:"operation"`
	Value     []string `json:"value"`
}

func Prepare(_service *services.Service) func() {
	return func() {
		WAFService.OnlineSince = time.Now().Unix()
		var err error
		var files []string

		rules, files, err = loadRules("rules/*.woof")
		if err != nil {
			panic(err)
		}

		WAFService.InfoLog(fmt.Sprintf("Loaded %d rules from following files:", len(rules)))
		var sb strings.Builder
		for _, file := range files {
			sb.WriteString(fmt.Sprintf("\t- %s", file))

			if file != files[len(files)-1] {
				sb.WriteString("\n")
			}
		}

		WAFService.InfoLog(sb.String())
	}
}

func MatchRules(ctx *fasthttp.RequestCtx) bool {
	defer func() {
		if r := recover(); r != nil {

		}
	}()

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
			return rule.Action == "block"
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
		ip := ctx.RemoteIP().String()
		country, _ := whois.GetCountry(ip)
		fieldValue = country
	case "ip.geoip.asnum":
		ip := ctx.RemoteIP().String()
		asn, _ := whois.GetASN(ip)
		asnStr := fmt.Sprintf("%d", asn)
		fieldValue = asnStr
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

func loadRules(pattern string) ([]Rule, []string, error) {
	files, err := filepath.Glob(pattern)
	if err != nil {
		return nil, nil, err
	}

	var allRules []Rule
	for _, file := range files {
		rules, err := loadRulesFromFile(file)
		if err != nil {
			return nil, nil, err
		}

		allRules = append(allRules, rules...)
	}

	return allRules, files, nil
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
