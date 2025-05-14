package postgresql

import (
	"context"
	"fmt"
	"sync"
	"wired/modules/env"
	"wired/modules/logger"

	"github.com/jackc/pgx/v4/pgxpool"
)

type DBManager struct {
	mu   sync.RWMutex
	pool map[string]*pgxpool.Pool
}

var Manager = &DBManager{
	pool: make(map[string]*pgxpool.Pool),
}

func (dbManager *DBManager) InitDB(name string) error {
	dbManager.mu.Lock()
	defer dbManager.mu.Unlock()

	connString := fmt.Sprintf(
		"postgres://%s:%s@%s:5432/%s?sslmode=disable",
		env.GetEnv("PSQL_USER", "wiredshield"),
		env.GetEnv("PSQL_PASSWORD", ""),
		env.GetEnv("PSQL_ADDR", "2.56.244.12"),
		name,
	)

	pool, err := pgxpool.Connect(context.Background(), connString)
	if err != nil {
		return fmt.Errorf("init db %s failed: %w", name, err)
	}

	dbManager.pool[name] = pool
	logger.Println("Connected to DB: ", name)
	return nil
}

func (dbManager *DBManager) GetPool(name string) *pgxpool.Pool {
	dbManager.mu.RLock()
	defer dbManager.mu.RUnlock()
	return dbManager.pool[name]
}
