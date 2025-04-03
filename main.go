package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/cors"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/joho/godotenv"

	"github.com/ryansaam/aa/db"
	"github.com/ryansaam/aa/handler"
)

func main() {
	ctx := context.Background()

	// init godotenv
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	// init db
	var dbURL string
	if os.Getenv("DATABASE_URL") != "" {
		dbURL = os.Getenv("DATABASE_URL")
	} else {
		log.Fatal("Error: No DATABASE_URL environment variable found: main.go: run() -> os.Getenv(\"DATABASE_URL\")")
	}

	dbpool, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to create connection pool: %v\n; main.go: run() -> pgxpool.New()", err)
		os.Exit(1)
	}
	defer dbpool.Close()

	queries := db.New(dbpool)

	// create api routes
	r := chi.NewRouter()

	// Set up CORS options
	corsOptions := cors.Options{
		// Only allow the specific origin for your frontend
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "OPTIONS"},
		AllowedHeaders:   []string{"Content-Type", "Authorization"},
		AllowCredentials: true,
		MaxAge:           300, // Max cache age in seconds
	}

	// check for required environment variables
	secret := os.Getenv("REFRESH_TOKEN_SECRET")
	if secret == "" {
		log.Printf("Refresh token secret missing in .env file; main() -> os.Getenv()\n")
		return
	}

	cipher := os.Getenv("CIPHER_KEY")
	if cipher == "" {
		log.Printf("Cipher key missing in .env file; main() -> os.Getenv()\n")
		return
	}

	stripePrivateKey := os.Getenv("STRIPE_PRIVATE_KEY")
	if stripePrivateKey == "" {
		log.Printf("Stripe private key missing in .env file; main() -> os.Getenv()\n")
		return
	}

	// routing
	r.Use(cors.Handler(corsOptions))

	r.Get("/aa", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("aa says hello!"))
	})

	r.Get("/aa/token", func(w http.ResponseWriter, r *http.Request) {
		handler.GetAccessToken(w, r, ctx, queries)
	})

	r.Post("/aa/login", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("aa says hello!"))
	})

	r.Post("/aa/signup", func(w http.ResponseWriter, r *http.Request) {
		handler.RegisterUser(w, r, ctx, queries, dbpool)
	})

	// serve api
	host := os.Getenv("HOST")
	if host == "" {
		http.ListenAndServe(":"+os.Getenv("PORT"), r)
	} else {
		addr := os.Getenv("HOST") + ":" + os.Getenv("PORT")
		server := http.Server{Addr: addr, Handler: r}
		fmt.Printf("Starting server on: http://%s \n", os.Getenv("HOST")+":"+os.Getenv("PORT"))
		if err := server.ListenAndServe(); err != nil {
			log.Fatalf("Failed to start server: %v", err)
		}
	}
}
