package main

import (
	"fmt"
	"time"
	"wiredshield/commands"
	wireddns "wiredshield/dns"
	"wiredshield/http"
	"wiredshield/modules/db"
	"wiredshield/modules/env"
	"wiredshield/services"
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
		{Key: "ssl", Desc: "SSL service", Fn: func(m *commands.Model) { go commands.Ssl(m) }},
	}

	dnsService := services.RegisterService("dns", "DNS Server")
	dnsService.Boot = wireddns.Prepare(dnsService)

	httpProxyService := services.RegisterService("http", "HTTP Proxy")
	httpProxyService.Boot = http.Prepare(httpProxyService)

	commands.Boot(nil)
	go func() {
		fmt.Println("Starting SSL service...")
		time.Sleep(2 * time.Second)
		fmt.Println("SSL service started.")
		commands.Ssl(nil)
	}()

	/*model := commands.InitialModel()
	p := tea.NewProgram(model)
	if _, err := p.Run(); err != nil {
		log.Fatal(err)
	}*/
}
