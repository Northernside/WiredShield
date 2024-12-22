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

	service.InfoLog("Connected to PostgreSQL")
}

type GeoLoc struct {
	Country string
	City    string
}

type Client struct {
	ID        int
	IPAddress string
	GeoLoc    GeoLoc
	PublicKey string
}

func GetClient(clientName string) (Client, error) {
	var client Client
	err := PsqlConn.QueryRow(context.Background(), "SELECT * FROM clients WHERE name = $1", clientName).Scan(&client.ID, &client.IPAddress, &client.GeoLoc.Country, &client.GeoLoc.City, &client.PublicKey)
	if err != nil {
		return client, err
	}

	return client, nil
}
