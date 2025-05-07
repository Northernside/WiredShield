package env

import (
	"bytes"
	"io"
	"os"
	"strings"
	"wired/modules/logger"
)

var (
	env = make(map[string]string)
)

func LoadEnvFile() {
	file, err := os.Open(".env")
	if err != nil {
		logger.Fatal("Failed to open .env file:", err)
	}
	defer file.Close()

	var buffer bytes.Buffer
	_, err = io.Copy(&buffer, file)
	if err != nil {
		logger.Fatal("Failed to read .env file:", err)
	}

	lines := strings.Split(buffer.String(), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "=") {
			parts := strings.SplitN(line, "=", 2)
			env[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
}

func GetEnv(key, defaultValue string) string {
	if value, exists := env[key]; exists {
		return value
	}

	logger.Printf("Warning: Environment variable %s not found\n", key)
	return defaultValue
}
