package utils

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
)

func GetFileHash(filePath string) ([]byte, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return nil, fmt.Errorf("failed to copy file content: %w", err)
	}

	hashBytes := hash.Sum(nil)
	return hashBytes, nil
}
