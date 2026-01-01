package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"time"

	"github.com/ehubscher/goidp/internal/authn"
	"github.com/joho/godotenv"
	_ "modernc.org/sqlite"
)

func main() {
	err := godotenv.Load(".env")
	if err != nil {
		log.Fatal(err)
	}

	router := http.NewServeMux()
	router.HandleFunc("GET /", func(rw http.ResponseWriter, r *http.Request) {
		rw.WriteHeader(http.StatusOK)
		fmt.Fprint(rw, "ROOT: under construction")
	})

	var host string = os.Getenv("SERVER_HOST")
	port, err := strconv.Atoi(os.Getenv("SERVER_PORT"))
	if err != nil {
		slog.Error("Failed to parse SERVER_PORT into int type. Double check configuration.")
		log.Fatalf("%v", err)
	}

	baseCtx, cancelBaseCtx := context.WithCancel(context.Background())

	var server = &http.Server{
		Addr:           fmt.Sprintf("%s:%d", host, port),
		Handler:        router,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20,
		BaseContext: func(l net.Listener) context.Context {
			return baseCtx
		},
	}

	slog.Info("Listening for request...", "host", host, "port", port)

	idleConnsClosed := make(chan struct{})
	go func() {
		sigint := make(chan os.Signal, 1)
		signal.Notify(sigint, os.Interrupt)
		<-sigint

		// We received an interrupt signal, shutdown.
		cancelBaseCtx()
		if err := server.Shutdown(baseCtx); err != nil {
			// Error from closing listeners or context timeout
			slog.Error("HTTP server Shutdown", "err", err)
		}

		close(idleConnsClosed)
	}()

	if err := server.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		// Error starting or closing listener
		slog.Error("HTTP server ListenAndServer", "err", err)
	}

	<-idleConnsClosed
	<-baseCtx.Done()

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
