package utils

import (
	"context"
	"errors"
	"log"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/ryansaam/aa/db"
)

type Claims struct {
	Id    string `json:"id"`
	Phone string `json:"phone_number"`
	jwt.RegisteredClaims
}
type AuthCredentials struct {
	ID          uuid.UUID `json:"id"`
	PhoneNumber string    `json:"phone_number"`
}

func InsertRefreshTokenForUser(subject, id string, expiresAt time.Time, ctx context.Context, queries *db.Queries) error {
	// convert data types to db types
	sub, err := uuid.Parse(subject)
	if err != nil {
		log.Println(err)
		return errors.New("could not parse uuid; utils.go: InsertRefreshTokenForUser() -> uuid.Parse(subject)")
	}
	jti, err := uuid.Parse(id)
	if err != nil {
		log.Println(err)
		return errors.New("could not parse uuid; utils.go: InsertRefreshTokenForUser() -> uuid.Parse(id)")
	}

	// insert refresh token into database
	params := db.InsertRefreshTokenParams{
		Sub: *UUIDToPgUUID(sub),
		Jti: *UUIDToPgUUID(jti),
		Exp: pgtype.Timestamptz{Time: expiresAt, Valid: true},
	}
	err = queries.InsertRefreshToken(ctx, params)
	if err != nil {
		log.Println(err)
		return errors.New("could not insert refresh token into database; utils.go: InsertRefreshTokenForUser()")
	}

	return nil
}
