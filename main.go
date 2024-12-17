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

	commands.Commands = []commands.Command{}

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
