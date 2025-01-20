package rules

import (
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

type Action int

const (
	Block Action = iota
	Allow
	Log
)

var (
	WAFService *services.Service
	actionName = map[Action]string{
		Block: "block",
		Allow: "allow",
		Log:   "log",
	}
)

type Rule struct {
	Expression string
	Action     Action
}

var (
	Rules = []Rule{}
)

func init() {
	WAFService := services.RegisterService("waf", "Web Application Firewall")
	WAFService.Boot = func() {
		includes := func(arr []string, item string) bool {
			for _, i := range arr {
				if i == item {
					return true
				}
			}

			return false
		}

		// load every *.woof file in rules/
		files, err := filepath.Glob("rules/*.woof")
		if err != nil {
			panic(err)
		}

		actions := []string{"block", "allow", "log"}
		for _, file := range files {
			action := strings.SplitN(filepath.Base(file), "_", 2)[0]
			if !includes(actions, action) {
				continue
			}

			fileContent, err := os.ReadFile(file)
			if err != nil {
				panic(err)
			}

			for _, rule := range strings.Split(strings.TrimSpace(string(fileContent)), "\n") {
				if rule == "" {
					continue
				}

				actionEnum := Block
				for k, v := range actionName {
					if v == action {
						actionEnum = k
						break
					}
				}

				Rules = append(Rules, Rule{
					Expression: rule,
					Action:     actionEnum,
				})
			}
		}

		WAFService.OnlineSince = time.Now().Unix()
		WAFService.InfoLog(fmt.Sprintf("Loaded %d rules", len(Rules)))
	}
}

func EvaluateRule(ctx *fasthttp.RequestCtx) bool {
	for _, rule := range Rules {
		if evaluateRule(ctx, rule) {
			switch rule.Action {
			case Block:
				ctx.Error("Access Denied", fasthttp.StatusForbidden)
			case Allow:
				return true
			case Log:
				WAFService.InfoLog(fmt.Sprintf("Rule matched: %s", rule.Expression))
			}
		}
	}

	return false
}

func evaluateRule(ctx *fasthttp.RequestCtx, rule Rule) bool {
	expr := rule.Expression
	ip := getIp(ctx)
	country, _ := whois.GetCountry(ip)
	asn, _ := whois.GetASN(ip)

	values := map[string]string{
		"ip.geoip.country":     country,
		"ip.geoip.asnum":       fmt.Sprintf("%d", asn),
		"http.user_agent":      string(ctx.UserAgent()),
		"http.request.method":  string(ctx.Method()),
		"http.request.version": string(ctx.Request.Header.Protocol()),
		"http.request.uri":     string(ctx.RequestURI()),
		"http.request.host":    string(ctx.Host()),
		"http.request.path":    string(ctx.Path()),
		"http.request.query":   string(ctx.QueryArgs().QueryString()),
		"http.request.body":    string(ctx.Request.Body()),
		"http.request.header":  string(ctx.Request.Header.Header()),
	}

	contains := func(field, value string) bool {
		if val, exists := values[field]; exists {
			return strings.Contains(val, value)
		}

		return false
	}

	equals := func(field, value string) bool {
		if val, exists := values[field]; exists {
			return val == value
		}
		return false
	}

	inSet := func(field, valueSet string) bool {
		if val, exists := values[field]; exists {
			set := strings.Split(strings.Trim(valueSet, "{}"), " ")
			for _, v := range set {
				if val == v {
					return true
				}
			}
		}

		return false
	}

	var evaluate func(string) bool
	evaluate = func(expr string) bool {
		expr = strings.TrimSpace(expr)
		if strings.HasPrefix(expr, "(") && strings.HasSuffix(expr, ")") {
			expr = strings.Trim(expr, "()")
		}

		if strings.Contains(expr, " and ") {
			parts := strings.Split(expr, " and ")
			for _, part := range parts {
				if !evaluate(part) {
					return false
				}
			}

			return true
		}

		if strings.Contains(expr, " or ") {
			parts := strings.Split(expr, " or ")
			for _, part := range parts {
				if evaluate(part) {
					return true
				}
			}

			return false
		}

		if strings.HasPrefix(expr, "not ") {
			return !evaluate(strings.TrimPrefix(expr, "not "))
		}

		if strings.Contains(expr, " contains ") {
			parts := strings.SplitN(expr, " contains ", 2)
			return contains(strings.TrimSpace(parts[0]), strings.Trim(parts[1], `"`))
		}

		if strings.Contains(expr, " eq ") {
			parts := strings.SplitN(expr, " eq ", 2)
			return equals(strings.TrimSpace(parts[0]), strings.Trim(parts[1], `"`))
		}

		if strings.Contains(expr, " in ") {
			parts := strings.SplitN(expr, " in ", 2)
			return inSet(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
		}

		return false
	}

	return evaluate(expr)
}

func getIp(reqCtx *fasthttp.RequestCtx) string {
	addr := reqCtx.RemoteAddr()
	ipAddr, ok := addr.(*net.TCPAddr)
	if !ok {
		return ""
	}

	return ipAddr.IP.String()
}
