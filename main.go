package main

import (
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"os"
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
		processService.InfoLog("Initializing WiredShield")
		go db.PInit(processService)
	}

	isMaster := env.GetEnv("MASTER", "false")
	if isMaster == "true" {
		masterHandling()
	} else {
		nodeHandling()
	}

	dnsService := services.RegisterService("dns", "DNS Server")
	dnsService.Boot = wireddns.Prepare(dnsService)

	httpsService := services.RegisterService("https", "HTTPS Server")
	httpsService.Boot = wiredhttps.Prepare(httpsService)

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

func masterHandling() {
	processService.InfoLog("Running as master")
	handleKeys("master")
}

func nodeHandling() {
	processService.InfoLog("Running as node")

	clientName := env.GetEnv("CLIENT_NAME", "unknown")
	if clientName == "unknown" {
		processService.FatalLog("CLIENT_NAME is not set")
	}

	handleKeys(clientName)

	masterHost := env.GetEnv("MASTER_API", "https://shield.as214428.net/")
	req, err := http.NewRequest("GET", masterHost+"/.wiredshield/proxy-auth", nil)
	if err != nil {
		processService.FatalLog(fmt.Sprintf("Failed to create request -> State: 1, %s, %s", masterHost+"/.wiredshield/proxy-auth", clientName))
	}

	req.Header.Set("State", "1")
	req.Header.Set("ws-client-name", clientName)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		processService.FatalLog(fmt.Sprintf("Failed to send proxy-auth request -> State: 1, %s, %s, %s", masterHost+"/.wiredshield/proxy-auth", clientName, err.Error()))
	}

	if resp.StatusCode != 200 {
		processService.FatalLog(fmt.Sprintf("Failed to send proxy-auth request -> State: 1, %s, %s, %d", masterHost+"/.wiredshield/proxy-auth", clientName, resp.StatusCode))
	}

	wsSigningCode := resp.Header.Get("ws-signing-code")
	processService.InfoLog(fmt.Sprintf("Received signing code: %s", wsSigningCode))

	req, err = http.NewRequest("GET", masterHost+"/.wiredshield/proxy-auth", nil)
	if err != nil {
		processService.FatalLog(fmt.Sprintf("Failed to create request -> State: 2, %s, %s", masterHost+"/.wiredshield/proxy-auth", clientName))
	}

	req.Header.Set("State", "2")

	privateKey, err := pgp.LoadPrivateKey(fmt.Sprintf("keys/%s-private.asc", clientName), "")
	if err != nil {
		processService.FatalLog(fmt.Sprintf("Failed to load private key -> %s, %s", clientName, err.Error()))
	}

	signingCode, err := pgp.SignMessage(string(wsSigningCode), privateKey)
	if err != nil {
		processService.FatalLog(fmt.Sprintf("Failed to sign message -> %s, %s", clientName, err.Error()))
	}

	b64SigningCode := base64.StdEncoding.EncodeToString([]byte(signingCode))
	req.Header.Set("ws-signing-code-signature", wsSigningCode)
	req.Header.Set("ws-signing-code-signature", b64SigningCode)

	resp, err = client.Do(req)
	if err != nil {
		processService.FatalLog(fmt.Sprintf("Failed to send proxy-auth request -> State: 2, %s, %s, %s", masterHost+"/.wiredshield/proxy-auth", clientName, err.Error()))
	}

	if resp.StatusCode != 200 {
		processService.FatalLog(fmt.Sprintf("Failed to send proxy-auth request -> State: 2, %s, %s, %d", masterHost+"/.wiredshield/proxy-auth", clientName, resp.StatusCode))
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

	processService.InfoLog("Keys found")
}
