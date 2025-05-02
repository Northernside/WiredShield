package postgresql

import (
	"context"
	"fmt"
	"wired/modules/env"
	"wired/modules/logger"

	"github.com/jackc/pgx/v4/pgxpool"
)

var (
	PsqlConn *pgxpool.Pool
)

func Init() {
	var err error
	connString := fmt.Sprintf(
		"postgres://%s:%s@%s:5432/%s?sslmode=disable",
		env.GetEnv("PSQL_USER", "wiredshield"),
		env.GetEnv("PSQL_PASSWORD", ""),
		env.GetEnv("PSQL_ADDR", "45.157.11.82"),
		env.GetEnv("PSQL_DB", "reverseproxy"),
	)

	PsqlConn, err = pgxpool.Connect(context.Background(), connString)
	if err != nil {
		logger.Fatalf("Unable to connect to database: %v\n", err)
		return
	}

	logger.Println("Connected to PostgreSQL")
}
