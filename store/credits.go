/*
FILE PATH: store/credits.go

Mode A fiat write credit management. Atomic deduction with row-level
locking prevents overdraft under concurrent submissions.

KEY ARCHITECTURAL DECISIONS:
  - SELECT FOR UPDATE: row lock serializes concurrent deductions.
  - Balance zero → ErrInsufficientCredits (HTTP 402 upstream).
  - BulkPurchase is UPSERT: idempotent for retry safety.
*/
package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// CreditStore manages Mode A write credits.
type CreditStore struct {
	db *pgxpool.Pool
}

// NewCreditStore creates a credit store.
func NewCreditStore(db *pgxpool.Pool) *CreditStore {
	return &CreditStore{db: db}
}

// DeductInTx atomically decrements one credit within the supplied
// transaction. Returns new balance. ErrInsufficientCredits if
// balance is zero.
//
// Useful when the caller already has a tx open and wants the
// credit deduction to share its commit boundary. Most callers
// should use Deduct instead — it manages its own transaction
// internally and lets the api/ side keep zero pgx imports
// (— Pure CQRS).
func (s *CreditStore) DeductInTx(ctx context.Context, tx pgx.Tx, exchangeDID string) (int64, error) {
	var balance int64
	err := tx.QueryRow(ctx,
		"SELECT balance FROM credits WHERE exchange_did = $1 FOR UPDATE",
		exchangeDID,
	).Scan(&balance)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, ErrInsufficientCredits
	}
	if err != nil {
		return 0, fmt.Errorf("store/credits: lock row: %w", err)
	}
	if balance <= 0 {
		return 0, ErrInsufficientCredits
	}

	newBalance := balance - 1
	_, err = tx.Exec(ctx,
		`UPDATE credits SET balance = $1, total_consumed = total_consumed + 1,
		 updated_at = NOW() WHERE exchange_did = $2`,
		newBalance, exchangeDID,
	)
	if err != nil {
		return 0, fmt.Errorf("store/credits: deduct: %w", err)
	}
	return newBalance, nil
}

// Deduct atomically decrements one credit, opening + committing
// its own ReadCommitted transaction internally. Returns
// ErrInsufficientCredits if the balance is zero.
//
// This is the api/ → CreditDeducter surface. The pgx.Tx-taking
// DeductInTx variant is preserved for callers that need to share
// a transaction (e.g., admission paths that bundle credit
// deduction with another DML in one commit).
func (s *CreditStore) Deduct(ctx context.Context, exchangeDID string) error {
	return WithReadCommittedTx(ctx, s.db, func(ctx context.Context, tx pgx.Tx) error {
		_, err := s.DeductInTx(ctx, tx, exchangeDID)
		return err
	})
}

// BulkPurchase adds credits. UPSERT for idempotent retries.
func (s *CreditStore) BulkPurchase(ctx context.Context, exchangeDID string, amount int64) (int64, error) {
	if amount <= 0 {
		return 0, fmt.Errorf("store/credits: purchase amount must be positive, got %d", amount)
	}
	var newBalance int64
	err := s.db.QueryRow(ctx, `
		INSERT INTO credits (exchange_did, balance, total_purchased, updated_at)
		VALUES ($1, $2, $2, NOW())
		ON CONFLICT (exchange_did) DO UPDATE SET
			balance = credits.balance + $2,
			total_purchased = credits.total_purchased + $2,
			updated_at = NOW()
		RETURNING balance`,
		exchangeDID, amount,
	).Scan(&newBalance)
	if err != nil {
		return 0, fmt.Errorf("store/credits: purchase: %w", err)
	}
	return newBalance, nil
}

// Balance returns the current credit balance for an exchange.
func (s *CreditStore) Balance(ctx context.Context, exchangeDID string) (int64, error) {
	var balance int64
	err := s.db.QueryRow(ctx,
		"SELECT balance FROM credits WHERE exchange_did = $1", exchangeDID,
	).Scan(&balance)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("store/credits: balance: %w", err)
	}
	return balance, nil
}
