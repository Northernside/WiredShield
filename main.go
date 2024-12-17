package main

import (
	"log"
	"wiredshield/commands"
	wireddns "wiredshield/dns"
	"wiredshield/http"
	"wiredshield/modules/db"
	"wiredshield/modules/env"
	"wiredshield/services"

	tea "github.com/charmbracelet/bubbletea"
)

func init() {
	env.LoadEnvFile()
}

func main() {
	db.Init()
	log.Println("LMDB initialized")

	commands.Commands = []commands.Command{
		{Key: "help", Desc: "Show this help message", Fn: commands.Help},
		{Key: "clear", Desc: "Clear the output", Fn: commands.Clear},
		{Key: "boot", Desc: "Boot all services", Fn: commands.Boot},
		{Key: "info", Desc: "Show service info", Fn: commands.Info},
		{Key: "dns", Desc: "DNS server", Fn: commands.Dns},
		{Key: "ssl", Desc: "SSL service", Fn: commands.Ssl},
	}

	dnsService := services.RegisterService("dns", "DNS Server")
	dnsService.Boot = wireddns.Prepare(dnsService)

	log.Println("DNS service registered")

	httpProxyService := services.RegisterService("http", "HTTP Proxy")
	log.Println("HTTP service registered 1")
	httpProxyService.Boot = http.Prepare(httpProxyService)

	log.Println("HTTP service registered 2")

	log.Println("Services registered")
	model := commands.InitialModel()
	p := tea.NewProgram(model)
	if _, err := p.Run(); err != nil {
		log.Fatal(err)
	}
}
