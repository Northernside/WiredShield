package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"time"
	"wiredshield/modules/env"
	"wiredshield/modules/pgp"
	"wiredshield/services"
	"wiredshield/utils/b64"
)

type AuthResponse struct {
	AccessToken string `json:"access_token"`
}

func NodeHandling() {
	services.ProcessService.InfoLog("Running as node")

	clientName := env.GetEnv("CLIENT_NAME", "unknown")
	if clientName == "unknown" {
		services.ProcessService.FatalLog("CLIENT_NAME is not set")
	}

	services.ClientName = clientName
	handleKeys(clientName)

	masterHost := env.GetEnv("MASTER_API", "https://shield.as214428.net/")
	handleProxyAuth(clientName, masterHost)
}

func handleProxyAuth(clientName, masterHost string) {
	dialer := &net.Dialer{
		Resolver: &net.Resolver{
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := &net.Dialer{Timeout: 5 * time.Second}
				return d.DialContext(ctx, "udp", "woof.ns.wired.rip:53")
			},
		},
	}

	client := &http.Client{
		Transport: &http.Transport{DialContext: dialer.DialContext},
	}

	// state 1: send initial proxy-auth request
	sendAuthRequest(client, masterHost, clientName, "1", "")

	// state 2: sign and resend request
	signingCode, accessToken := signAndSend(client, masterHost, clientName)
	services.ProcessAccessToken = accessToken
	services.ProcessService.InfoLog(fmt.Sprintf("Received access token: %s", accessToken))

	services.ProcessService.InfoLog(fmt.Sprintf("Node '%s' successfully authenticated with signing code: %s",
		clientName, signingCode))
}

func sendAuthRequest(client *http.Client, masterHost, clientName, state, signature string) {
	req, err := http.NewRequest("GET", fmt.Sprintf("%s.wiredshield/proxy-auth", masterHost), nil)
	if err != nil {
		services.ProcessService.FatalLog(fmt.Sprintf("Failed to create request -> State: %s, %s, %s",
			state, masterHost, err.Error()))
	}

	req.Header.Set("State", state)
	req.Header.Set("ws-client-name", clientName)

	if state == "2" && signature != "" {
		req.Header.Set("ws-signing-code-signature", signature)
	}

	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != 200 {
		services.ProcessService.FatalLog(fmt.Sprintf("Failed to send proxy-auth request -> State: %s, %s, %d",
			state, masterHost, resp.StatusCode))
	}
}

func signAndSend(client *http.Client, masterHost, clientName string) (string, string) {
	req, err := http.NewRequest("GET", fmt.Sprintf("%s.wiredshield/proxy-auth", masterHost), nil)
	if err != nil {
		services.ProcessService.FatalLog(fmt.Sprintf("Failed to create request -> State: 2, %s, %s",
			masterHost, err.Error()))
	}

	signingCode := requestSigningCode(client, req)
	privateKeyPath := fmt.Sprintf("certs/%s-private.asc", clientName)
	privateKey, err := pgp.LoadPrivateKey(privateKeyPath, "")
	if err != nil {
		services.ProcessService.FatalLog(fmt.Sprintf("Failed to load private key -> %s, %s",
			clientName, err.Error()))
	}

	signedMessage, err := pgp.SignMessage(signingCode, privateKey)
	if err != nil {
		services.ProcessService.FatalLog(fmt.Sprintf("Failed to sign message -> %s, %s",
			clientName, err.Error()))
	}

	signature := b64.Encode(signedMessage)
	sendAuthRequest(client, masterHost, clientName, "2", signature)

	resp := getAuthResponse(client, req)
	return signingCode, resp.AccessToken
}

func requestSigningCode(client *http.Client, req *http.Request) string {
	resp, err := client.Do(req)
	if err != nil {
		services.ProcessService.FatalLog("Failed to send proxy-auth request -> State: 1")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		services.ProcessService.FatalLog("Unexpected status code while sending proxy-auth request" +
			"-> State: 1, Status Code: " + resp.Status)
	}

	signingCode := resp.Header.Get("ws-signing-code")
	if signingCode == "" {
		services.ProcessService.FatalLog("Missing ws-signing-code in response headers")
	}

	return signingCode
}

func getAuthResponse(client *http.Client, req *http.Request) AuthResponse {
	resp, err := client.Do(req)
	if err != nil {
		services.ProcessService.FatalLog("Failed to send proxy-auth request -> State: 2")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		services.ProcessService.FatalLog("Unexpected status code while sending proxy-auth request" +
			"-> State: 2, Status Code: " + resp.Status)
	}

	var authResponse AuthResponse
	err = json.NewDecoder(resp.Body).Decode(&authResponse)
	if err != nil {
		services.ProcessService.FatalLog("Failed to decode proxy-auth response body: " + err.Error())
	}

	if authResponse.AccessToken == "" {
		services.ProcessService.FatalLog("Missing access token in proxy-auth response")
	}

	return authResponse
}
