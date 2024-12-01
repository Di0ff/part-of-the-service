package main

import (
	"authn-service/internal/db"
	h "authn-service/internal/http"
	"log"
	"net/http"
)

func main() {
	data, err := db.Connection()
	defer data.Close()

	http.HandleFunc("/auth/access", h.AccessHandler)
	http.HandleFunc("/auth/refresh", h.RefreshHandler)

	err = http.ListenAndServe(":8080", nil)
	if err != nil {
		log.Fatalf("ОШИБКА запуска сервера: %v", err)
	}
}
