package main

import (
	"log"
	"wiredshield/commands"
	wireddns "wiredshield/dns"
	"wiredshield/modules/db"
	"wiredshield/modules/env"
	"wiredshield/services"

	tea "github.com/charmbracelet/bubbletea"
)

func main() {
	env.LoadEnvFile()
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

	model := commands.InitialModel()
	p := tea.NewProgram(model)
	if _, err := p.Run(); err != nil {
		log.Fatal(err)
	}
}
