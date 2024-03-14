package main

import (
	"database/sql"
	"fmt"
	"log/slog"
	"os"

	"github.com/joho/godotenv"
	_ "modernc.org/sqlite"
)

func main() {
	err := godotenv.Load(".env")
	if err != nil {
		slog.Error("Error loading .env file: %s", err)
	}

	var dbFileName string = fmt.Sprintf("%s.sqlite", os.Getenv("DB_NAME"))

	dbFile, err := os.Create(dbFileName)
	if err != nil {
		slog.Error(err.Error())
	}
	defer dbFile.Close()

	db, err := sql.Open("sqlite", dbFileName)
	if err != nil {
		slog.Error("Error creating SQLite database: %s", err)
	}
	defer db.Close()

	var createUsersQuery string = `CREATE TABLE users (
		id INTEGER PRIMARY KEY,
		first_name VARCHAR(255) NOT NULL,
		last_name VARCHAR(255) NOT NULL,
		email VARCHAR(255) NOT NULL
	 );`

	res, err := db.Exec(createUsersQuery)
	if err != nil {
		slog.Error("Error creating users table: %s", err)
	}

	slog.Info(fmt.Sprint(res.RowsAffected()))
}