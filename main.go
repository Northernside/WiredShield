package main

import (
	"fmt"
	"log"
	"os"
	"strings"
	"wiredshield/commands"
	wireddns "wiredshield/dns"
	"wiredshield/http"
	"wiredshield/modules/db"
	"wiredshield/modules/env"
	"wiredshield/services"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
)

func init() {
	env.LoadEnvFile()
}

func main() {
	db.Init()

	commands.Commands = []commands.Command{
		{Key: "help", Desc: "Show this help message", Fn: commands.Help},
		{Key: "clear", Desc: "Clear the output", Fn: commands.Clear},
		{Key: "boot", Desc: "Boot all services", Fn: commands.Boot},
		{Key: "info", Desc: "Show service info", Fn: commands.Info},
		{Key: "dns", Desc: "DNS server", Fn: commands.Dns},
		{Key: "ssl", Desc: "SSL service", Fn: commands.Ssl},
	}

	// check if args are passed
	if len(os.Args) > 1 {
		// run ssl command
		if os.Args[1] == "ssl" {
			command := commands.Commands[5]
			_model := commands.Model{
				TextInput: textinput.NewModel(),
			}

			_model.TextInput.SetValue(strings.Join(os.Args[1:], " "))
			fmt.Println(_model.TextInput.Value())

			command.Fn(&_model)
			return
		}
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

	model.Output += "Goodbye!\n"
}
