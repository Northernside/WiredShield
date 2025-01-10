package main

import (
	"log"
	"os"
	"time"
	"wiredshield/commands"
	"wiredshield/handlers"
	"wiredshield/modules/db"
	"wiredshield/modules/env"
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

	// CLI args handler
	args := os.Args[1:]
	if len(args) > 0 {
		handlers.HandleArgs(args)
	}

	// setup master/node handling
	if env.GetEnv("MASTER", "false") == "true" {
		handlers.MasterHandling()
	} else {
		handlers.NodeHandling()
	}

	// boot services
	handlers.BootServices()

	// start TUI
	model := commands.InitialModel()
	p := tea.NewProgram(model)
	if _, err := p.Run(); err != nil {
		log.Fatal(err)
	}
}
