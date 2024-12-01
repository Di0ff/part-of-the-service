package access

import (
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"os"
	"time"
)

type Claims struct {
	UUID string `json:"uuid"`
	IP   string `json:"ip"`
	jwt.RegisteredClaims
}

func Generate(uuid, ip string) (string, error) {
	key := []byte(os.Getenv("Key"))

	claims := Claims{
		UUID: uuid,
		IP:   ip,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(72 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	signedToken, err := token.SignedString(key)
	if err != nil {
		return "", fmt.Errorf("ОШИБКА подписания: %v", err)
	}

	return signedToken, nil
}

func Check(signedToken string) (*Claims, error) {
	key := []byte(os.Getenv("Key"))

	token, err := jwt.ParseWithClaims(signedToken, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("ОШИБКА неверный метод")
		}

		return key, nil
	})

	if err != nil {
		return nil, fmt.Errorf("ОШИБКА парсинга: %v", err)
	}

	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		return claims, nil
	}

	return nil, fmt.Errorf("ОШИБКА невалидный токен")
}
