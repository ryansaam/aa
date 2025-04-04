package handler

import (
	"context"
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"os"

	"github.com/google/uuid"
	"github.com/ryansaam/aa/db"
	"github.com/ryansaam/aa/utils"
)

func writeAccessTokenResponse(write http.ResponseWriter, encryptedToken []byte, errMessage string) {
	write.Header().Set("Content-Type", "application/json")
	type Response struct {
		Token string `json:"token"`
		Error string `json:"error"`
	}
	response := &Response{
		Token: utils.Encode64(encryptedToken),
		Error: errMessage,
	}
	err := json.NewEncoder(write).Encode(response)
	if err != nil {
		log.Printf("Can't responed to access token request: writeAccessTokenResponse() -> json.NewEncoder().Encode(); error: %v\n", err)
	}
}

// GetAccessToken validates the refresh token from the secure cookie and issues an access token.
func GetAccessToken(write http.ResponseWriter, request *http.Request, ctx context.Context, queries *db.Queries) {
	internalServerErrorMsg := "Sorry, we're having trouble processing your request. Try again later."

	claims, err := utils.ExtractRefreshTokenClaims(request)
	if err != nil {
		// Handle the error: set headers, log the error, and send an error response.
		write.Header().Set("WWW-Authenticate", "Bearer")
		write.WriteHeader(http.StatusUnauthorized)
		writeAccessTokenResponse(write, []byte{}, "Unauthorized request")
		return
	}

	// Check if the refresh token is blacklisted.
	jti, err := uuid.Parse(claims.RegisteredClaims.ID)
	if err != nil {
		log.Printf("Could not parse token jti: GetAccessToken() -> uuid.Parse(); error: %v\n", err)
		write.WriteHeader(http.StatusInternalServerError)
		writeAccessTokenResponse(write, []byte{}, internalServerErrorMsg)
		return
	}

	_, err = queries.CheckIfTokenIsBlacklisted(ctx, *utils.UUIDToPgUUID(jti))
	if err != nil && err != sql.ErrNoRows {
		log.Printf("Database error while checking blacklist: GetAccessToken() -> queries.CheckIfTokenIsBlacklisted(); error: %v\n", err)
		write.WriteHeader(http.StatusInternalServerError)
		writeAccessTokenResponse(write, []byte{}, internalServerErrorMsg)
		return
	}
	if err == nil {
		log.Printf("Blacklisted refresh token attempted: GetAccessToken() -> queries.CheckIfTokenIsBlacklisted(); error: %v\n", err)
		write.WriteHeader(http.StatusUnauthorized)
		writeAccessTokenResponse(write, []byte{}, "Unauthorized request")
		return
	}

	// Retrieve the authentic user using the subject from the token claims.
	sub, err := uuid.Parse(claims.RegisteredClaims.Subject)
	if err != nil {
		log.Printf("Failed to parse subject uuid: GetAccessToken() -> uuid.Parse(); error: %v\n", err)
		write.WriteHeader(http.StatusInternalServerError)
		writeAccessTokenResponse(write, []byte{}, internalServerErrorMsg)
		return
	}

	authenticUser, err := queries.GetAuthenticUserWithID(ctx, *utils.UUIDToPgUUID(sub))
	if err != nil {
		if err == sql.ErrNoRows {
			log.Printf("User does not exist for the given token: GetAccessToken() -> queries.GetAuthenticUserWithID(); error: %v\n", err)
			write.WriteHeader(http.StatusUnauthorized)
			writeAccessTokenResponse(write, []byte{}, "User doesn't exist")
			return
		}
		log.Printf("Error retrieving user: GetAccessToken() -> queries.GetAuthenticUserWithID(); error: %v\n", err)
		write.WriteHeader(http.StatusInternalServerError)
		writeAccessTokenResponse(write, []byte{}, internalServerErrorMsg)
		return
	}

	// Create a new access token using the user's credentials.
	credentials := utils.AuthCredentials{
		ID:    authenticUser.ID,
		Email: authenticUser.Email,
	}
	token, err := utils.GenerateToken(credentials)
	if err != nil {
		log.Printf("Could not generate access token: GetAccessToken() -> utils.GenerateToken(); error: %v\n", err)
		write.WriteHeader(http.StatusInternalServerError)
		writeAccessTokenResponse(write, []byte{}, internalServerErrorMsg)
		return
	}

	// Encrypt the access token.
	encryptedToken, err := utils.Encrypt([]byte(token), []byte(os.Getenv("CIPHER_KEY")))
	if err != nil {
		log.Printf("Could not encrypt access token: GetAccessToken() -> utils.Encrypt(); error: %v\n", err)
		write.WriteHeader(http.StatusInternalServerError)
		writeAccessTokenResponse(write, []byte{}, internalServerErrorMsg)
		return
	}

	// Respond with the encrypted access token.
	write.WriteHeader(http.StatusOK)
	writeAccessTokenResponse(write, encryptedToken, "")
}
