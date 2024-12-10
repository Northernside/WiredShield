package main

import (
	"log"
	"os"
	"wiredshield/commands"
	wireddns "wiredshield/dns"
	"wiredshield/http"
	"wiredshield/modules/db"
	"wiredshield/modules/env"
	"wiredshield/services"

	tea "github.com/charmbracelet/bubbletea"
)

func main() {
	// disable log output
	dummyWriter, _ := os.Open(os.DevNull)
	log.SetOutput(dummyWriter)

	env.LoadEnvFile()
	db.Init()

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

	httpProxyService := services.RegisterService("http", "HTTP Proxy")
	httpProxyService.Boot = http.Prepare(httpProxyService)

	model := commands.InitialModel()
	p := tea.NewProgram(model)
	if _, err := p.Run(); err != nil {
		log.Fatal(err)
	}
}
