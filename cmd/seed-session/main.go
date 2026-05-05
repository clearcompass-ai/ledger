/*
FILE PATH: cmd/seed-session/main.go

seed-session — local-dev / CI helper that mints a Mode A session
token + credit balance for an exchange DID.

The ledger's admission middleware (api/middleware/auth.go)
validates Bearer tokens against the `sessions` table; the credits
table tracks per-exchange balances that are deducted atomically
inside admission's transaction.

Production deployments mint sessions through an exchange-side
service (or a thin admin API surface). This CLI is the test-mode
equivalent: a single command does both inserts so an ledger
running locally can `POST /v1/entries` with Bearer auth without
hand-crafting SQL.

Usage:

	go run ./cmd/seed-session \
	    -dsn "postgres://attesta:attesta@localhost:5544/attesta_test?sslmode=disable" \
	    -token "tok-dev" \
	    -did "did:key:z6MkpTHR8VNsBxYAAWHut2..." \
	    -credits 100 \
	    -ttl 24h

Flags fall back to env:

	-dsn → LEDGER_DATABASE_URL
	-did → if empty, a fresh did:key is generated and printed
	            (caller must capture it for the matching submit
	            client; ephemeral keys are never persisted here).

After running, POST /v1/entries with `Authorization: Bearer <token>`
deducts one credit per submission until the balance is exhausted
or the session expires.
*/
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	sdkdid "github.com/clearcompass-ai/attesta/did"

	"github.com/clearcompass-ai/ledger/store"
)

func main() {
	var (
		dsn = flag.String("dsn", os.Getenv("LEDGER_DATABASE_URL"), "Postgres DSN (defaults to $LEDGER_DATABASE_URL)")
		token = flag.String("token", "", "session token to mint (required)")
		didStr = flag.String("did", "", "exchange DID; empty → generate a fresh did:key and print it")
		credits = flag.Int64("credits", 100, "initial credit balance to seed")
		ttl = flag.Duration("ttl", 24*time.Hour, "session lifetime from now")
	)
	flag.Parse()

	if *dsn == "" {
		log.Fatal("seed-session: -dsn required (or set LEDGER_DATABASE_URL)")
	}
	if *token == "" {
		log.Fatal("seed-session: -token required")
	}
	if *credits <= 0 {
		log.Fatalf("seed-session: -credits must be positive, got %d", *credits)
	}

	exchangeDID := *didStr
	if exchangeDID == "" {
		kp, err := sdkdid.GenerateDIDKeySecp256k1()
		if err != nil {
			log.Fatalf("seed-session: generate did:key: %v", err)
		}
		exchangeDID = kp.DID
		fmt.Printf("generated exchange did:key (private key NOT persisted — capture for submit client):\n %s\n", exchangeDID)
	}

	ctx := context.Background()
	pool, err := pgxpool.New(ctx, *dsn)
	if err != nil {
		log.Fatalf("seed-session: connect: %v", err)
	}
	defer pool.Close()

	expiresAt := time.Now().UTC().Add(*ttl)
	if _, err := pool.Exec(ctx,
		`INSERT INTO sessions (token, exchange_did, expires_at)
		 VALUES ($1, $2, $3)
		 ON CONFLICT (token) DO UPDATE SET
		   exchange_did = EXCLUDED.exchange_did,
		   expires_at = EXCLUDED.expires_at`,
		*token, exchangeDID, expiresAt,
	); err != nil {
		log.Fatalf("seed-session: insert session: %v", err)
	}

	creditStore := store.NewCreditStore(pool)
	balance, err := creditStore.BulkPurchase(ctx, exchangeDID, *credits)
	if err != nil {
		log.Fatalf("seed-session: BulkPurchase: %v", err)
	}

	fmt.Printf("seeded:\n")
	fmt.Printf("  token = %s\n", *token)
	fmt.Printf("  exchange_did = %s\n", exchangeDID)
	fmt.Printf("  expires_at = %s\n", expiresAt.Format(time.RFC3339))
	fmt.Printf("  balance = %d credits\n", balance)
	fmt.Printf("\nuse with:\n curl -H 'Authorization: Bearer %s' http://localhost:8080/v1/...\n", *token)
}
