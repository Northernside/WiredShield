package handlers

import (
	"fmt"
	"os"
	"strings"
	"wiredshield/modules/db"
	"wiredshield/modules/pgp"
	"wiredshield/services"
)

func HandleArgs(args []string) {
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

		clientName := args[1]
		ip := args[2]

		// load public key
		_, err := pgp.LoadPublicKey(fmt.Sprintf("certs/%s-public.asc", clientName))
		if err != nil {
			fmt.Println("public key not found")
			os.Exit(1)
		}

		// create & insert client
		client := createClient(clientName, ip)
		db.PInit(services.ProcessService)
		if err = db.InsertClient(client); err != nil {
			fmt.Println("failed to insert client into db")
			os.Exit(1)
		}

		printClientInfo(client)
		os.Exit(0)
	default:
		fmt.Println("Unknown command")
		os.Exit(1)
	}
}

func createClient(name, ip string) services.Client {
	split := strings.Split(name, "-")
	return services.Client{
		Name:      name,
		IPAddress: ip,
		GeoLoc:    services.GeoLoc{Country: split[0], City: split[1]},
	}
}

func printClientInfo(client services.Client) {
	fmt.Printf("New client added:\n\tName: %s\n\tIP Address: %s\n\tCountry: %s\n\tCity: %s\n",
		client.Name, client.IPAddress, client.GeoLoc.Country, client.GeoLoc.City)
}
