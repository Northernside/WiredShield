package main

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"log"
	"os"
	"wiredshield/commands"
	ssl "wiredshield/commands/e"
	wireddns "wiredshield/dns"
	"wiredshield/http"
	"wiredshield/modules/db"
	"wiredshield/modules/env"
	"wiredshield/services"
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
		{Key: "ssl", Desc: "SSL service", Fn: func(model *commands.Model) { go commands.Ssl(model) }},
	}

	dnsService := services.RegisterService("dns", "DNS Server")
	dnsService.Boot = wireddns.Prepare(dnsService)

	go func() {
		commands.Boot(nil)
		fmt.Println("Generating account key and certificate for dawg.pics")
		accountKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			fmt.Printf("failed to generate account key: %v", err)
			return
		}

		dnsProvider := &ssl.ExampleDNSProvider{}
		domain := "dawg.pics"

		err = ssl.GenerateCertificate(dnsProvider, domain, accountKey)
		if err != nil {
			fmt.Printf("failed to generate certificate: %v", err)
			return
		}
	}()

	httpProxyService := services.RegisterService("http", "HTTP Proxy")
	httpProxyService.Boot = http.Prepare(httpProxyService)

	/*model := commands.InitialModel()
	p := tea.NewProgram(model)
	if _, err := p.Run(); err != nil {
		log.Fatal(err)
	}*/

	select {}
}
