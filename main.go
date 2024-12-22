package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
	"wiredshield/commands"
	wireddns "wiredshield/dns"
	wiredhttps "wiredshield/http"
	"wiredshield/modules/db"
	"wiredshield/modules/env"
	"wiredshield/modules/pgp"
	"wiredshield/services"

	tea "github.com/charmbracelet/bubbletea"
)

func init() {
	env.LoadEnvFile()
}

// TODO: service.XYZLog is (heavily) blocking the main thread

var processService *services.Service

func main() {
	db.Init()

	processService = services.RegisterService("process", "WiredShield")
	processService.Boot = func() {
		processService.OnlineSince = time.Now().Unix()
		processService.InfoLog("Initializing WiredShield")
		go db.PInit(processService)
	}

	args := os.Args[1:]
	if len(args) > 0 {
		handleArgs(args)
	}

	isMaster := env.GetEnv("MASTER", "false")
	if isMaster == "true" {
		masterHandling()
	} else {
		nodeHandling()
	}

	if (env.GetEnv("TMP_BYPASS", "false")) == "false" {
		dnsService := services.RegisterService("dns", "DNS Server")
		dnsService.Boot = wireddns.Prepare(dnsService)

		httpsService := services.RegisterService("https", "HTTPS Server")
		httpsService.Boot = wiredhttps.Prepare(httpsService)
	} else {
		processService.WarnLog("TMP: Bypassing DNS and HTTPS services")
	}

	commands.Commands = []commands.Command{
		{Key: "help", Desc: "Show this help message", Fn: commands.Help},
		{Key: "clear", Desc: "Clear the output", Fn: commands.Clear},
		{Key: "boot", Desc: "Boot all services", Fn: commands.Boot},
		{Key: "info", Desc: "Show service info", Fn: commands.Info},
		{Key: "dns", Desc: "DNS server", Fn: commands.Dns},
	}

	model := commands.InitialModel()
	p := tea.NewProgram(model)
	if _, err := p.Run(); err != nil {
		log.Fatal(err)
	}
}

func handleArgs(args []string) {
	switch args[0] {
	case "help":
		fmt.Println("Usage: wiredshield [add-client]")
		fmt.Println("add-client <client-name> <ip-address> - Add a new client")
		os.Exit(0)
	case "add-client":
		if len(args) < 2 {
			fmt.Println("Usage: wiredshield add-client <client-name> <ip-address>")
			os.Exit(1)
		}

		services.ClientName = args[1]
		_, err := pgp.LoadPublicKey(fmt.Sprintf("certs/%s-public.asc", services.ClientName))
		if err != nil {
			fmt.Println("Public key not found")
			os.Exit(1)
		}

		// insert into db
		var client db.Client
		client.Name = services.ClientName
		client.IPAddress = args[2]

		split := strings.Split(services.ClientName, "-")
		client.GeoLoc.Country = split[0]
		client.GeoLoc.City = split[1]

		db.PInit(processService)
		err = db.InsertClient(client)
		if err != nil {
			fmt.Println("Failed to insert client into db")
			os.Exit(1)
		}

		fmt.Println("New client added:")
		fmt.Println("\tName:", client.Name)
		fmt.Println("\tIP Address:", client.IPAddress)
		fmt.Println("\tCountry:", client.GeoLoc.Country)
		fmt.Println("\tCity:", client.GeoLoc.City)

		os.Exit(0)
	default:
		fmt.Println("Unknown command")
		os.Exit(1)
	}
}

func masterHandling() {
	processService.InfoLog("Running as master")
	handleKeys("master")
}

func nodeHandling() {
	processService.InfoLog("Running as node")

	services.ClientName = env.GetEnv("CLIENT_NAME", "unknown")
	if services.ClientName == "unknown" {
		processService.FatalLog("CLIENT_NAME is not set")
	}

	handleKeys(services.ClientName)

	masterHost := env.GetEnv("MASTER_API", "https://shield.as214428.net/")
	req, err := http.NewRequest("GET", masterHost+".wiredshield/proxy-auth", nil)
	if err != nil {
		processService.FatalLog(fmt.Sprintf("Failed to create request -> State: 1, %s, %s", masterHost+".wiredshield/proxy-auth", services.ClientName))
	}

	req.Header.Set("State", "1")
	req.Header.Set("ws-client-name", services.ClientName)

	client := &http.Client{}
	dialer := &net.Dialer{
		Resolver: &net.Resolver{
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{
					Timeout: time.Second * 5,
				}

				return d.DialContext(ctx, "udp", "woof.ns.wired.rip:53")
			},
		},
	}

	client.Transport = &http.Transport{
		DialContext: dialer.DialContext,
	}

	resp, err := client.Do(req)
	if err != nil {
		processService.FatalLog(fmt.Sprintf("Failed to send proxy-auth request -> State: 1, %s, %s, %s", masterHost+".wiredshield/proxy-auth", services.ClientName, err.Error()))
	}

	if resp.StatusCode != 200 {
		processService.FatalLog(fmt.Sprintf("Failed to send proxy-auth request -> State: 1, %s, %s, %d", masterHost+".wiredshield/proxy-auth", services.ClientName, resp.StatusCode))
	}

	wsSigningCode := resp.Header.Get("ws-signing-code")
	processService.InfoLog(fmt.Sprintf("Received signing code: %s", wsSigningCode))

	req, err = http.NewRequest("GET", masterHost+".wiredshield/proxy-auth", nil)
	if err != nil {
		processService.FatalLog(fmt.Sprintf("Failed to create request -> State: 2, %s, %s", masterHost+".wiredshield/proxy-auth", services.ClientName))
	}

	req.Header.Set("State", "2")

	privateKey, err := pgp.LoadPrivateKey(fmt.Sprintf("certs/%s-private.asc", services.ClientName), "")
	if err != nil {
		processService.FatalLog(fmt.Sprintf("Failed to load private key -> %s, %s", services.ClientName, err.Error()))
	}

	signingCode, err := pgp.SignMessage(string(wsSigningCode), privateKey)
	if err != nil {
		processService.FatalLog(fmt.Sprintf("Failed to sign message -> %s, %s", services.ClientName, err.Error()))
	}

	b64SigningCode := base64.StdEncoding.EncodeToString([]byte(signingCode))
	req.Header.Set("ws-signing-code", wsSigningCode)
	req.Header.Set("ws-signing-code-signature", b64SigningCode)
	req.Header.Set("ws-client-name", services.ClientName)

	resp, err = client.Do(req)
	if err != nil {
		processService.FatalLog(fmt.Sprintf("Failed to send proxy-auth request -> State: 2, %s, %s, %s", masterHost+".wiredshield/proxy-auth", services.ClientName, err.Error()))
	}

	if resp.StatusCode != 200 {
		processService.FatalLog(fmt.Sprintf("Failed to send proxy-auth request -> State: 2, %s, %s, %d", masterHost+".wiredshield/proxy-auth", services.ClientName, resp.StatusCode))
	}

	services.ProcessAccessToken = resp.Header.Get("ws-access-token")
	processService.InfoLog(fmt.Sprintf("Received access token: %s", services.ProcessAccessToken))
}

func handleKeys(clientName string) {
	// check if pgp key exists
	// check file certs/%s-public.asc && certs/%s-private.asc
	// if not, generate new keypair

	publicKeyPath := fmt.Sprintf("certs/%s-public.asc", clientName)
	privateKeyPath := fmt.Sprintf("certs/%s-private.asc", clientName)

	// check with os.Stat if the files exist
	_, err := os.Stat(publicKeyPath)
	if err != nil {
		// generate new keypair
		processService.InfoLog("Public key not found, generating new keypair")
		err = pgp.GenerateKeyPair(clientName)
		if err != nil {
			processService.FatalLog(fmt.Sprintf("Failed to generate keypair -> %s", err.Error()))
		}
	}

	_, err = os.Stat(privateKeyPath)
	if err != nil {
		processService.FatalLog("Private key not found, generating new keypair")
		err = pgp.GenerateKeyPair(clientName)
		if err != nil {
			processService.FatalLog(fmt.Sprintf("Failed to generate keypair -> %s", err.Error()))
		}
	}

	if env.GetEnv("MASTER", "false") == "true" {
		services.ServerPrivateKey, err = pgp.LoadPrivateKey(privateKeyPath, "")
		if err != nil {
			processService.FatalLog(fmt.Sprintf("Failed to load private key -> %s", err.Error()))
		}
	}

	processService.InfoLog("Keys found")
}
