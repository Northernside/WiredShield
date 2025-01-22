package main

import (
	"log"
	"os"
	"time"
	"wiredshield/commands"
	"wiredshield/handlers"
	"wiredshield/modules/db"
	"wiredshield/modules/env"
	"wiredshield/modules/rules"
	"wiredshield/services"

	tea "github.com/charmbracelet/bubbletea"
)

func init() {
	env.LoadEnvFile()
}

func main() {
	// critical process inits
	db.Init()
	services.ProcessService = services.RegisterService("process", "WiredShield")
	services.ProcessService.Boot = func() {
		services.ProcessService.OnlineSince = time.Now().Unix()
		services.ProcessService.InfoLog("Initializing WiredShield")
		go db.PInit(services.ProcessService)
	}

	rules.WAFService = services.RegisterService("waf", "WiredShield")
	rules.WAFService.Boot = rules.Prepare(rules.WAFService)

	// CLI args handler
	args := os.Args[1:]
	if len(args) > 0 {
		handlers.HandleArgs(args)
	}

	// setup master/node handling
	if env.GetEnv("MASTER", "false") == "true" {
		handlers.MasterHandling()
		services.ClientName = env.GetEnv("CLIENT_NAME", "unknown")
	} else {
		handlers.NodeHandling()
	}

	// boot services
	handlers.PrepareServices()

	// start TUI
	model := commands.InitialModel()
	p := tea.NewProgram(model)
	if _, err := p.Run(); err != nil {
		log.Fatal(err)
	}
}
