package main

import (
	"database/sql"
	"fmt"
	"log"
	"log/slog"
	"os"

	"github.com/ehubscher/goidp/internal/authn"
	"github.com/joho/godotenv"
	_ "modernc.org/sqlite"
)

func main() {
	err := godotenv.Load(".env")
	if err != nil {
		log.Fatal(err)
	}

	argon2idB64Hash, err := authn.GenerateHash("argon2id", "password123")
	if err != nil {
		log.Fatalf("Failed to generate password hash: %v", err)
	}
	fmt.Printf("argon2id base64-encoded hash: %s\n", argon2idB64Hash)

	bcryptB64Hash, err := authn.GenerateHash("bcrypt", "password123")
	if err != nil {
		log.Fatalf("Failed to generate password hash: %v", err)
	}
	fmt.Printf("bcrypt base64-encoded hash: %s\n", bcryptB64Hash)

	var dbFileName string = fmt.Sprintf("%s.sqlite", os.Getenv("DB_NAME"))
	db, err := sql.Open("sqlite", dbFileName)
	if err != nil {
		slog.Error("Error connecting SQLite database: %s", err)
	}
	defer db.Close()

	stmt, err := db.Prepare(`INSERT INTO users(email, password_hash) VALUES(?,?)`)
	if err != nil {
		slog.Error("Cannot prepare SQL query for insert into users table.", "err", err)
		log.Fatal(err)
	}

	res, err := stmt.Exec("example1@email.com", argon2idB64Hash)
	if err != nil {
		slog.Error("Cannot insert into users table.", "err", err)
		log.Fatal(err)
	}

	rows, err := res.RowsAffected()
	if err != nil {
		log.Fatal(err)
	}

	slog.Info("Succesfully inserted user.", "rows", rows)

	res, err = db.Exec(`INSERT INTO users(email, password_hash) VALUES(?,?)`, "example2@email.com", bcryptB64Hash)
	if err != nil {
		slog.Error("Cannot insert into users table.", "err", err)
		log.Fatal(err)
	}

	rows, err = res.RowsAffected()
	if err != nil {
		log.Fatal(err)
	}

	slog.Info("Succesfully inserted user.", "rows", rows)
}
