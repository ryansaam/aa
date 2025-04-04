package utils

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
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

// extractRefreshTokenClaims extracts, decodes, decrypts, and parses the refresh token from the secure cookie.
// It returns the JWT claims if successful, or an error otherwise.
func ExtractRefreshTokenClaims(request *http.Request) (*Claims, error) {
	cipherKey := os.Getenv("CIPHER_KEY")

	// Retrieve the refresh token from the secure cookie.
	cookie, err := request.Cookie("refresh_token")
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve refresh token cookie: %w", err)
	}

	// Decode the base64 encoded refresh token.
	encryptedRefreshToken, err := Decode64(cookie.Value)
	if err != nil {
		return nil, fmt.Errorf("failed to decode refresh token: %w", err)
	}

	// Decrypt the refresh token using the configured cipher key.
	refreshTokenDecryptedByte, err := Decrypt(encryptedRefreshToken, []byte(cipherKey))
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt refresh token: %w", err)
	}

	// Parse and validate the refresh token with JWT claims.
	claims := &Claims{}
	_, err = jwt.ParseWithClaims(string(refreshTokenDecryptedByte), claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(os.Getenv("REFRESH_TOKEN_SECRET")), nil
	})
	if err != nil {
		// Use string comparisons to determine the error cause. In a production system, consider using type assertions.
		if err.Error() == fmt.Sprintf("%s: %s", jwt.ErrTokenInvalidClaims.Error(), jwt.ErrSignatureInvalid.Error()) {
			return nil, fmt.Errorf("invalid refresh token signature: %w", err)
		}
		if err.Error() == fmt.Sprintf("%s: %s", jwt.ErrTokenInvalidClaims.Error(), jwt.ErrTokenExpired.Error()) {
			return nil, fmt.Errorf("expired refresh token: %w", err)
		}
		return nil, fmt.Errorf("unhandled token error: %w", err)
	}
	return claims, nil
}
