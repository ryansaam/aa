package utils

import (
	"context"
	"errors"
	"log"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/ryansaam/aa/db"
)

type Claims struct {
	Id    string `json:"id"`
	Email string `json:"email"`
	jwt.RegisteredClaims
}
type AuthCredentials struct {
	ID    pgtype.UUID `json:"id"`
	Email string      `json:"email"`
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

// CreateEncryptedRefreshToken generates a JWT with standard claims,
// signs it with the REFRESH_TOKEN_SECRET, then encrypts it with CIPHER_KEY.
// Returns the encrypted token and the token ID (jti) for DB storage.
func CreateEncryptedRefreshToken(userID uuid.UUID) (encrypted []byte, jti string, exp time.Time, err error) {
	// Load secrets from env
	refreshSecret := os.Getenv("REFRESH_TOKEN_SECRET")
	cipherKey := os.Getenv("CIPHER_KEY")

	// Token claims
	jtiUUID := uuid.New()
	jti = jtiUUID.String()
	exp = time.Now().Add(90 * 24 * time.Hour).Truncate(time.Millisecond)
	now := time.Now().Truncate(time.Millisecond)

	claims := &Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID.String(),
			ExpiresAt: &jwt.NumericDate{Time: exp},
			ID:        jti,
			Issuer:    "Knomor AA service",
			IssuedAt:  &jwt.NumericDate{Time: now},
		},
	}

	// Create and sign token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString([]byte(refreshSecret))
	if err != nil {
		return nil, "", time.Time{}, err
	}

	// Encrypt the token
	encrypted, err = Encrypt([]byte(signed), []byte(cipherKey))
	if err != nil {
		return nil, "", time.Time{}, err
	}

	return encrypted, jti, exp, nil
}

func GenerateToken(user AuthCredentials) (string, error) {
	expirationTime := time.Now().Add(15 * time.Minute)
	expirationTime = expirationTime.Truncate(time.Millisecond)

	claims := &Claims{
		Id:    user.ID.String(),
		Email: user.Email,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: &jwt.NumericDate{Time: expirationTime},
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	signedToken, err := token.SignedString([]byte(os.Getenv("ACCESS_TOKEN_SECRET")))

	if err != nil {
		log.Println("Could not sign token; tokens.go: GenerateToken() -> token.SignedString()")
		return "", err
	}

	return signedToken, nil
}
