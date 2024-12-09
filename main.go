package main

import (
	"log"
	"wiredshield/commands"
	wireddns "wiredshield/dns"
	"wiredshield/services"

	tea "github.com/charmbracelet/bubbletea"
)

func main() {
	commands.Commands = []commands.Command{
		{Key: "help", Desc: "Show this help message", Fn: commands.Help},
		{Key: "clear", Desc: "Clear the output", Fn: commands.Clear},
		{Key: "boot", Desc: "Boot all services", Fn: commands.Boot},
		{Key: "info", Desc: "Show service info", Fn: commands.Info},
	}

	service := services.RegisterService("dns", "DNS Server")
	service.Boot = wireddns.Prepare(service)

	model := commands.InitialModel()
	p := tea.NewProgram(model)
	if _, err := p.Run(); err != nil {
		log.Fatal(err)
	}
}
