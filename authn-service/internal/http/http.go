package http

import (
	"authn-service/internal/db"
	"authn-service/internal/tokens/access"
	"authn-service/internal/tokens/refresh"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
)

func AccessHandler(w http.ResponseWriter, r *http.Request) {
	data, _ := db.Connection()
	defer data.Close()

	var request struct {
		UUID string `json:"uuid"`
	}

	body, _ := ioutil.ReadAll(r.Body)
	defer r.Body.Close()

	err := json.Unmarshal(body, &request)
	if err != nil || request.UUID == "" {
		http.Error(w, "ОШИБКА в параметрах запроса", http.StatusBadRequest)
		return
	}

	uuidUser := request.UUID
	ip := r.RemoteAddr

	tokenA, _ := access.Generate(uuidUser, ip)
	tokenR, _ := refresh.Generate()

	db.Add(data, uuidUser, tokenR)

	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(fmt.Sprintf(`{"access_token": "%v", "refresh_token": "%v"}`, tokenA, tokenR)))
}

func RefreshHandler(w http.ResponseWriter, r *http.Request) {
	data, _ := db.Connection()
	defer data.Close()

	var request struct {
		TokenA string `json:"access_token"`
		TokenR string `json:"refresh_token"`
	}

	body, _ := ioutil.ReadAll(r.Body)
	defer r.Body.Close()

	err := json.Unmarshal(body, &request)
	if err != nil {
		http.Error(w, "ОШИБКА в параметрах запроса", http.StatusBadRequest)
		return
	}

	claims, _ := access.Check(request.TokenA)

	uuid := claims.UUID
	oldIp := claims.IP

	hash, _ := db.Get(data, uuid)

	if !db.Check(hash, request.TokenR) {
		http.Error(w, "ОШИБКА неверный токен", http.StatusUnauthorized)
		return
	}

	ip := r.RemoteAddr
	if oldIp != ip {
		sendEmailWarning(uuid, oldIp, ip)
		http.Error(w, "IP-адрес изменился", http.StatusUnauthorized)
		return
	}

	newTokenA, _ := access.Generate(uuid, ip)

	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(fmt.Sprintf(`{"access_token": "%v"}`, newTokenA)))
}

func sendEmailWarning(uuid, oldIP, newIP string) {
	fmt.Printf("Предупреждение для пользователя %v: IP-адрес изменился с %v на %v\n", uuid, oldIP, newIP)
}
