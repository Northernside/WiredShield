package db

import (
	"context"
	"fmt"
	"wiredshield/services"

	_env "wiredshield/modules/env"

	"github.com/jackc/pgx/v4/pgxpool"
)

var (
	PsqlConn *pgxpool.Pool
)

func PInit(service *services.Service) {
	var err error
	connString := fmt.Sprintf(
		"postgres://%s:%s@localhost:5432/%s?sslmode=disable",
		_env.GetEnv("PSQL_USER", "wiredshield"),
		_env.GetEnv("PSQL_PASSWORD", ""),
		_env.GetEnv("PSQL_DB", "reverseproxy"),
	)

	PsqlConn, err = pgxpool.Connect(context.Background(), connString)
	if err != nil {
		service.FatalLog(fmt.Sprintf("failed to connect to database: %v", err))
	}

	// create client table if not exists
	_, err = PsqlConn.Exec(context.Background(), "CREATE TABLE IF NOT EXISTS clients (name TEXT PRIMARY KEY, ip_address TEXT, country TEXT, city TEXT)")
	if err != nil {
		service.FatalLog(fmt.Sprintf("failed to create clients table: %v", err))
	}

	service.InfoLog("Connected to PostgreSQL")
}

type GeoLoc struct {
	Country string
	City    string
}

type Client struct {
	Name      string
	IPAddress string
	GeoLoc    GeoLoc
}

func GetClient(clientName string) (Client, error) {
	var client Client
	err := PsqlConn.QueryRow(context.Background(), "SELECT * FROM clients WHERE name = $1", clientName).Scan(&client.Name, &client.IPAddress, &client.GeoLoc.Country, &client.GeoLoc.City)
	if err != nil {
		return client, err
	}

	return client, nil
}

func InsertClient(client Client) error {
	_, err := PsqlConn.Exec(context.Background(), "INSERT INTO clients (name, ip_address, country, city) VALUES ($1, $2, $3, $4)", client.Name, client.IPAddress, client.GeoLoc.Country, client.GeoLoc.City)
	return err
}