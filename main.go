package main

import (
	"log"
	"wiredshield/commands"
	stress_target "wiredshield/debug/stress"
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

// TODO: service.XYZLog is (heavily) blocking the main thread

func main() {
	db.Init()

	commands.Commands = []commands.Command{
		{Key: "help", Desc: "Show this help message", Fn: commands.Help},
		{Key: "clear", Desc: "Clear the output", Fn: commands.Clear},
		{Key: "boot", Desc: "Boot all services", Fn: commands.Boot},
		{Key: "info", Desc: "Show service info", Fn: commands.Info},
		{Key: "dns", Desc: "DNS server", Fn: commands.Dns},
	}

	dnsService := services.RegisterService("dns", "DNS Server")
	dnsService.Boot = wireddns.Prepare(dnsService)

	httpProxyService := services.RegisterService("http", "HTTP Proxy")
	httpProxyService.Boot = http.Prepare(httpProxyService)

	httpStressTestInstance := services.RegisterService("http_stt", "HTTP Stress Test Target")
	httpStressTestInstance.Boot = stress_target.Prepare(httpStressTestInstance)

	model := commands.InitialModel()
	p := tea.NewProgram(model)
	if _, err := p.Run(); err != nil {
		log.Fatal(err)
	}
}
