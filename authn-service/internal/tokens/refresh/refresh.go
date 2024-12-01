package refresh

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

func Generate() (string, error) {
	refresh := make([]byte, 32)
	_, err := rand.Read(refresh)
	if err != nil {
		return "", fmt.Errorf("ОШИБКА генерации: %v", err)
	}

	encoded := base64.StdEncoding.EncodeToString(refresh)

	return encoded, nil
}
