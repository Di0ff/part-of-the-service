package db

import (
	"database/sql"
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"os"

	_ "github.com/lib/pq"
)

func Connection() (*sql.DB, error) {
	url := os.Getenv("dbUrl")
	db, err := sql.Open("postgres", url)
	if err != nil {
		return nil, fmt.Errorf("ОШИБКА подключения к БД: %v", err)
	}

	return db, nil
}

func Add(db *sql.DB, uuidUser, refresh string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(refresh), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("ОШИБКА хеширования токена: %v", err)
	}

	_, err = db.Exec("INSERT INTO refresh (user_uuid, hash) VALUES ($1, $2)",
		uuidUser, hash)
	if err != nil {
		return fmt.Errorf("ОШИБКА добавления хеша: %v", err)
	}

	return nil
}

func Get(db *sql.DB, uuidUser string) (string, error) {
	var hash string

	err := db.QueryRow("SELECT hash FROM refresh WHERE user_uuid=$1",
		uuidUser).Scan(&hash)
	if err != nil {
		return "", fmt.Errorf("ОШИБКА получения hash: %v", err)
	} else if err == sql.ErrNoRows {
		return "", fmt.Errorf("ОШИБКА токена не существует: %v", uuidUser)
	}

	return hash, nil
}

func Check(hashInDB, oldRefresh string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashInDB), []byte(oldRefresh))
	return err == nil
}
