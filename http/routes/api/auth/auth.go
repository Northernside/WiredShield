package routes

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"time"

	"wiredshield/modules/jwt"
	"wiredshield/services"

	"github.com/valyala/fasthttp"
)

var (
	WhitelistedIds = []string{}
	AuthService    = services.RegisterService("auth", "Auth Provider")
)

func init() {
	AuthService.Boot = func() {
		AuthService.OnlineSince = time.Now().Unix()

		file, err := os.OpenFile("whitelist.txt", os.O_RDONLY, 0644)
		if err != nil {
			log.Println("Failed to open whitelist file")
			return
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			WhitelistedIds = append(WhitelistedIds, scanner.Text())
		}

		if err := scanner.Err(); err != nil {
			log.Println("Failed to read whitelist file")
			return
		}

		AuthService.InfoLog("Auth provider initialized")
		AuthService.InfoLog(fmt.Sprintf("Whitelist initialized with %d ids", len(WhitelistedIds)))
	}
}

func Auth(ctx *fasthttp.RequestCtx) {
	if !ctx.IsGet() {
		ctx.Error("Invalid request method", fasthttp.StatusMethodNotAllowed)
		return
	}

	// token query param
	token := string(ctx.QueryArgs().Peek("token"))
	if token == "" {
		ctx.Error("Missing token parameter", fasthttp.StatusBadRequest)
		return
	}

	// validate token
	claims, err := jwt.ValidateToken(token)
	if err != nil {
		ctx.Error("Invalid token", fasthttp.StatusUnauthorized)
		return
	}

	// check if user is whitelisted
	for _, id := range WhitelistedIds {
		if id == claims["discord_id"] {
			ctx.Response.Header.Set("Set-Cookie", fmt.Sprintf("token=%s; Path=/; Max-Age=604800", token))
			ctx.Redirect("/", fasthttp.StatusFound)
			return
		}
	}

	ctx.Error("User not whitelisted", fasthttp.StatusForbidden)
}
